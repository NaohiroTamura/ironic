#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
iRMC Vendor Driver
"""
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import importutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LI
from ironic.common.i18n import _LW
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers import base
from ironic.drivers.modules import agent
from ironic.drivers.modules.irmc import common as irmc_common
from ironic.drivers.modules.irmc import deploy as irmc_deploy
from ironic.drivers.modules import pxe
from ironic.drivers.modules import snmp

scci = importutils.try_import('scciclient.irmc.scci')

CONF = cfg.CONF

LOG = logging.getLogger(__name__)

# SC2.mib: sc2srvCurrentBootStatus
BOOT_STATUS_OID = "1.3.6.1.4.1.231.2.10.2.2.10.4.1.1.4.1"
BOOT_STATUS = [
    None,
    'unknown',              # unknown(1)
    'off',                  # off(2)
    'no-boot-cpu',          # no-boot-cpu(3)
    'self-test',            # self-test(4)
    'setup',                # setup(5)
    'os-boot',              # os-boot(6)
    'diagnostic-boot',      # diagnostic-boot(7)
    'os-running',           # os-running(8)
    'diagnostic-running',   # diagnostic-running(9)
    'os-shutdown',          # os-shutdown(10)
    'diagnostic-shutdown',  # diagnostic-shutdown(11)
    'reset',                # reset(12)
]

VENDOR_ACTION = {
    scci.POWER_SOFT_OFF: 'graceful shutdown',
    scci.POWER_RAISE_NMI: 'raise nmi',
}


def _vendor_power_action(task, action):
    """Perform vendor specific power action.

    :param task: a TaskManager instance containing the node to act on.
    :param action: a SCCI command
    :raises: IRMCOperationError, iRMC and SCCI specific error
    :raises: PowerStateFailure, power status retrieval error
    :raises: other exceptions by the node's power driver if something
             wrong occurred during the power action.
    """
    node = task.node
    target_state = (states.POWER_ON if action == scci.POWER_RAISE_NMI
                    else states.POWER_OFF)

    try:
        curr_state = task.driver.power.get_power_state(task)

    except Exception as e:
        with excutils.save_and_reraise_exception():
            node.last_error = _("Failed to get the current power state."
                                "Error: %(error)s") % {'error': e}
            node.target_power_state = states.NOSTATE
            node.save()

    if curr_state == states.POWER_OFF:
        node.last_error = None
        node.power_state = states.POWER_OFF
        node.target_power_state = states.NOSTATE
        node.save()
        LOG.warn(_LW("Not going to change node power state because "
                     "current state is already POWER_OFF."))
        return

    elif curr_state == states.POWER_ON:
        node.last_error = None
        node.power_state = states.POWER_ON
        node.target_power_state = target_state
        node.save()

    else:  # curr_state == states.ERROR
        node.last_error = _("Power driver returned ERROR state "
                            "while trying to sync power state.")
        node.power_state = states.ERROR
        node.target_power_state = states.NOSTATE
        node.save()
        raise exception.PowerStateFailure(node.last_error)

    # issue SCCI command
    irmc_client = irmc_common.get_irmc_client(node)
    try:
        irmc_client(action)
    except scci.SCCIClientError as irmc_exception:
        node.last_error = _(
            "iRMC %(action)s failed for node %(node_id)s. "
            "Error: %(error)s") % {'action': VENDOR_ACTION[action],
                                   'node_id': node.uuid,
                                   'error': irmc_exception}
        node.target_power_state = states.NOSTATE
        node.save()

        LOG.error(node.last_error)
        raise exception.IRMCOperationError(
            operation=VENDOR_ACTION[action], error=irmc_exception)

    LOG.info(
        _LI('iRMC %(action)s has initiatted for %(node_id)s.'),
        {'action': VENDOR_ACTION[action], 'node_id': node.uuid})

    # check if iRMC acknowledged the shutdown of the node OS instance or not
    snmp_irmc = snmp.SNMPClient(node.driver_info['irmc_address'],
                                CONF.irmc.snmp_port,
                                CONF.irmc.snmp_version,
                                CONF.irmc.snmp_community,
                                CONF.irmc.snmp_security)
    bootstatus_value = None
    interval = CONF.irmc.snmp_polling_interval
    max_retry = int(CONF.irmc.state_transition_timeout / interval)
    try:
        for i in range(0, max_retry):
            bootstatus_value = snmp_irmc.get(BOOT_STATUS_OID)
            LOG.debug("iRMC SNMP agent of %(node_id)s returned "
                      "boot status value %(bootstatus)s at %(times)s."
                      % {'node_id': node.uuid,
                         'bootstatus': BOOT_STATUS[bootstatus_value],
                         'times': i})
            if ((action == scci.POWER_SOFT_OFF and
                 bootstatus_value in (1, 2)) or
                (action == scci.POWER_RAISE_NMI and
                 bootstatus_value == 8)):
                break
            time.sleep(interval)

    except exception.SNMPFailure as snmp_exception:
        node.last_error = _(
            "iRMC %(action)s failed for node %(node_id)s "
            " during the final confirmation. "
            "Error: %(error)s") % {'action': VENDOR_ACTION[action],
                                   'node_id': node.uuid,
                                   'error': snmp_exception}
        node.power_state = states.ERROR
        node.target_power_state = states.NOSTATE
        node.save()

        LOG.error(node.last_error)
        raise exception.IRMCOperationError(
            operation=VENDOR_ACTION[action], error=snmp_exception)

    if ((action == scci.POWER_SOFT_OFF and
         bootstatus_value not in (1, 2)) or
        (action == scci.POWER_RAISE_NMI and bootstatus_value != 8)):
        # iRMC failed to acknowledge the state transition completion
        node.last_error = _(
            "iRMC %(action)s failed to acknowledge the state "
            "transition completion for node %(node_id)s."
            "Error: iRMC reteruend unexpected boot status value "
            "%(bootstatus)s.") % {
                'action': VENDOR_ACTION[action],
                'node_id': node.uuid,
                'bootstatus': BOOT_STATUS[bootstatus_value]}
        node.power_state = states.ERROR
        node.target_power_state = states.NOSTATE
        node.save()

        LOG.error(node.last_error)
        error = _('unexpected boot status value')
        raise exception.IRMCOperationError(
            VENDOR_ACTION[action], error=error)

    else:
        # iRMC acknowledged the shutdown, everything went okay
        node.last_error = None
        node.power_state = target_state
        node.target_power_state = states.NOSTATE
        node.save()

        LOG.info(_LI('iRMC %(action) successfully set node '
                     '%(node_id)s power state to %(bootstatus)s.'),
                 {'action': VENDOR_ACTION[action],
                  'node_id': node.uuid,
                  'bootstatus': BOOT_STATUS[bootstatus_value]})


class VendorPassthru(base.VendorInterface):
    """Vendor-specific interfaces for iRMC power drivers."""

    def get_properties(self):
        irmc_prop = irmc_common.COMMON_PROPERTIES
        super_prop = super(VendorPassthru, self).get_properties()
        return dict(list(irmc_prop.items()) + list(super_prop.items()))

    def validate(self, task, method, **kwargs):
        """Validate vendor-specific actions.

        Checks if a valid vendor passthru method was passed and validates
        the parameters for the vendor passthru method.

        :param task: a TaskManager instance containing the node to act on.
        :param method: method to be validated.
        :param kwargs: kwargs containing the vendor passthru method's
            parameters.
        :raises: InvalidParameterValue, if any of the parameters have invalid
            value.
        """
        if method in ('graceful_shutdown', 'raise_nmi'):
            if {k: v for (k, v) in kwargs.items() if k is not 'http_method'}:
                raise exception.InvalidParameterValue(_(
                    "Method '%s' doesn't take any parameter.") % method)
            irmc_common.parse_driver_info(task.node)
        else:
            super(VendorPassthru, self).validate(task, method, **kwargs)

    @base.passthru(['POST'])
    @task_manager.require_exclusive_lock
    def graceful_shutdown(self, task, **kwargs):
        """Turns the server shutdown gracefully

        :param task: a TaskManager instance containing the node to act on.
        :raises: IRMCOperationError, iRMC and SCCI specific error
        :raises: PowerStateFailure, power status retrieval error
        :raises: other exceptions by the node's power driver if something
                 wrong occurred during the power action.
        """
        _vendor_power_action(task, scci.POWER_SOFT_OFF)

    @base.passthru(['POST'])
    @task_manager.require_exclusive_lock
    def raise_nmi(self, task, **kwargs):
        """Pulse the NMI (Non Maskable Interrupt)

        :param task: a TaskManager instance containing the node to act on.
        :raises: IRMCOperationError, iRMC and SCCI specific error
        :raises: PowerStateFailure, power status retrieval error
        :raises: other exceptions by the node's power driver if something
                 wrong occurred during the power action.
        """
        _vendor_power_action(task, scci.POWER_RAISE_NMI)


class IRMCPxeVendorPassthru(VendorPassthru, pxe.VendorPassthru):
    """Vendor-specific interfaces for iRMC power and pxe drivers."""
    pass


class IRMCIscsiVendorPassthru(VendorPassthru, irmc_deploy.VendorPassthru):
    """Vendor-specific interfaces for iRMC power and iscsi drivers."""
    pass


class IRMCAgentVendorPassthru(VendorPassthru, agent.AgentVendorInterface):
    """Vendor-specific interfaces for iRMC power and agent drivers."""
    pass
