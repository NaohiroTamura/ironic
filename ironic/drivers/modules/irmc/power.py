# Copyright 2015 FUJITSU LIMITED
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
iRMC Power Driver using the Base Server Profile
"""
import time

from ironic_lib import metrics_utils
from oslo_log import log as logging
from oslo_utils import importutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LI
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers import base
from ironic.drivers.modules import ipmitool
from ironic.drivers.modules.irmc import boot as irmc_boot
from ironic.drivers.modules.irmc import common as irmc_common
from ironic.drivers.modules import snmp

scci = importutils.try_import('scciclient.irmc.scci')

LOG = logging.getLogger(__name__)


METRICS = metrics_utils.get_metrics_logger(__name__)

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

if scci:
    STATES_MAP = {states.POWER_OFF: scci.POWER_OFF,
                  states.POWER_ON: scci.POWER_ON,
                  states.REBOOT: scci.POWER_RESET,
                  states.REBOOT_SOFT: scci.POWER_SOFT_CYCLE,
                  states.POWER_OFF_SOFT: scci.POWER_SOFT_OFF,
                  states.INJECT_NMI: scci.POWER_RAISE_NMI}


def _wait_power_state(task, target_state):
    """Wait for having changed to the target power state.

    :param task: a TaskManager instance containing the node to act on.
    :raises: IRMCOperationError if attaching virtual media failed.
    :raises: InvalidParameterValue if the validation of the
        ManagementInterface fails.
    """
    node = task.node
    d_info = irmc_common.parse_driver_info(node)
    snmp_client = snmp.SNMPClient(d_info['irmc_address'],
                                  d_info['irmc_snmp_port'],
                                  d_info['irmc_snmp_version'],
                                  d_info['irmc_snmp_community'],
                                  d_info['irmc_snmp_security'])

    interval = CONF.irmc.snmp_polling_interval
    max_retry = int(CONF.irmc.retry_timeout_soft / interval)

    try:
        for i in range(0, max_retry):
            bootstatus_value = snmp_client.get(BOOT_STATUS_OID)
            LOG.debug("iRMC SNMP agent of %(node_id)s returned "
                      "boot status value %(bootstatus)s at %(times)s."
                      % {'node_id': node.uuid,
                         'bootstatus': BOOT_STATUS[bootstatus_value],
                         'times': i})
            if ((target_state == states.POWER_SOFT_OFF and
                 bootstatus_value in (1, 2)) or
                (target_state in (states.REBOOT_SOFT, states.INJECT_NMI) and
                 bootstatus_value == 8)):
                break
            time.sleep(interval)

            try:
                manager_utils.chan(node.uuid).get(block=False)
                LOG.debug('Channel of node %(node)s got cancel messsage.',
                          {'node': node.uuid})
                raise exception.IRMCOperationError(
                    operation=target_state, error="canceled")
            except queue.Empty:
                LOG.debug('Channel of node %(node)s is empty.',
                          {'node': node.uuid})

    except exception.SNMPFailure as snmp_exception:
        node.last_error = _(
            "iRMC failed to acknowledge the target state "
            "for node %(node_id)s."
            "Error: %(error)s") % {'node_id': node.uuid,
                                   'error': snmp_exception}
        node.power_state = states.ERROR
        node.target_power_state = states.NOSTATE
        node.save()

        LOG.error(node.last_error)
        raise exception.IRMCOperationError(
            operation=target_state, error=snmp_exception)

    if ((target_state == states.POWER_SOFT_OFF and
         bootstatus_value not in (1, 2)) or
        (target_state in (states.REBOOT_SOFT, states.INJECT_NMI) and
         bootstatus_value != 8)):
        # iRMC failed to acknowledge the target state
        node.last_error = _(
            "iRMC failed to acknowledge the target state "
            "for node %(node_id)s."
            "Error: iRMC reteruend unexpected boot status value "
            "%(bootstatus)s.") % {
                'node_id': node.uuid,
                'bootstatus': BOOT_STATUS[bootstatus_value]}
        node.power_state = states.ERROR
        node.target_power_state = states.NOSTATE
        node.save()

        LOG.error(node.last_error)
        error = _('unexpected boot status value')
        raise exception.IRMCOperationError(
            operation=target_state, error=error)

    else:
        # iRMC acknowledged the target state
        node.last_error = None
        node.power_state = target_state
        node.target_power_state = states.NOSTATE
        node.save()

        LOG.info(_LI('iRMC successfully set node %(node_id)s '
                     'power state to %(bootstatus)s.'),
                 {'node_id': node.uuid,
                  'bootstatus': BOOT_STATUS[bootstatus_value]})


def _set_power_state(task, target_state):
    """Turns the server power on/off or do a reboot.

    :param task: a TaskManager instance containing the node to act on.
    :param target_state: target state of the node.
    :raises: InvalidParameterValue if an invalid power state was specified.
    :raises: MissingParameterValue if some mandatory information
        is missing on the node
    :raises: IRMCOperationError on an error from SCCI
    """

    node = task.node
    irmc_client = irmc_common.get_irmc_client(node)

    if target_state in (states.POWER_ON, states.REBOOT):
        irmc_boot.attach_boot_iso_if_needed(task)

    try:
        irmc_client(STATES_MAP[target_state])

    except KeyError:
        msg = _("_set_power_state called with invalid power state "
                "'%s'") % target_state
        raise exception.InvalidParameterValue(msg)

    except scci.SCCIClientError as irmc_exception:
        LOG.error(_LE("iRMC set_power_state failed to set state to %(tstate)s "
                      " for node %(node_id)s with error: %(error)s"),
                  {'tstate': target_state, 'node_id': node.uuid,
                   'error': irmc_exception})
        operation = _('iRMC set_power_state')
        raise exception.IRMCOperationError(operation=operation,
                                           error=irmc_exception)

    if target_state in (states.REBOOT_SOFT, states.POWER_OFF_SOFT,
                        states.INJECT_NMI):
        _wait_power_state(task, target_state)


class IRMCPower(base.PowerInterface):
    """Interface for power-related actions."""

    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """
        return irmc_common.COMMON_PROPERTIES

    @METRICS.timer('IRMCPower.validate')
    def validate(self, task):
        """Validate the driver-specific Node power info.

        This method validates whether the 'driver_info' property of the
        supplied node contains the required information for this driver to
        manage the power state of the node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue if required driver_info attribute
                 is missing or invalid on the node.
        :raises: MissingParameterValue if a required parameter is missing.
        """
        irmc_common.parse_driver_info(task.node)

    @METRICS.timer('IRMCPower.get_power_state')
    def get_power_state(self, task):
        """Return the power state of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :returns: a power state. One of :mod:`ironic.common.states`.
        :raises: InvalidParameterValue if required ipmi parameters are missing.
        :raises: MissingParameterValue if a required parameter is missing.
        :raises: IPMIFailure on an error from ipmitool (from _power_status
            call).
        """
        irmc_common.update_ipmi_properties(task)
        ipmi_power = ipmitool.IPMIPower()
        return ipmi_power.get_power_state(task)

    @METRICS.timer('IRMCPower.set_power_state')
    @task_manager.require_exclusive_lock
    def set_power_state(self, task, power_state):
        """Set the power state of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :param power_state: Any power state from :mod:`ironic.common.states`.
        :raises: InvalidParameterValue if an invalid power state was specified.
        :raises: MissingParameterValue if some mandatory information
            is missing on the node
        :raises: IRMCOperationError if failed to set the power state.
        """
        _set_power_state(task, power_state)

    @METRICS.timer('IRMCPower.reboot')
    @task_manager.require_exclusive_lock
    def reboot(self, task):
        """Perform a hard reboot of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue if an invalid power state was specified.
        :raises: IRMCOperationError if failed to set the power state.
        """
        current_pstate = self.get_power_state(task)
        if current_pstate == states.POWER_ON:
            _set_power_state(task, states.REBOOT)
        elif current_pstate == states.POWER_OFF:
            _set_power_state(task, states.POWER_ON)

    def get_supported_power_states(self, task):
        """Get a list of the supported power states.

        :param task: A TaskManager instance containing the node to act on.
            currently not used.
        :returns: A list with the supported power states defined
                  in :mod:`ironic.common.states`.
        """
        return [states.POWER_ON, states.POWER_OFF, states.REBOOT,
                states.REBOOT_SOFT, states.POWER_OFF_SOFT,
                states.INJECT_NMI,
                states.CANCEL_REBOOT_SOFT, states.CANCEL_POWER_OFF_SOFT,
                states.CANCEL_INJECT_NMI]
