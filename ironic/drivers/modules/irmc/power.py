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
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import importutils

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LI
from ironic.common.i18n import _LW
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers import base
from ironic.drivers.modules import ipmitool
from ironic.drivers.modules.irmc import common as irmc_common
from ironic.drivers.modules.irmc import deploy as irmc_deploy
from ironic.drivers.modules import pxe

scci = importutils.try_import('scciclient.irmc.scci')

CONF = cfg.CONF

LOG = logging.getLogger(__name__)

if scci:
    STATES_MAP = {states.POWER_OFF: scci.POWER_OFF,
                  states.POWER_ON: scci.POWER_ON,
                  states.REBOOT: scci.POWER_RESET}


def _attach_boot_iso_if_needed(task):
    """Attaches boot ISO for a deployed node if it exists.

    This method checks the instance info of the bare metal node for a
    boot ISO. If the instance info has a value of key 'irmc_boot_iso',
    it indicates that 'boot_option' is 'netboot'. Threfore it attaches
    the boot ISO on the bare metal node and then sets the node to boot from
    virtual media cdrom.

    :param task: a TaskManager instance containing the node to act on.
    :raises: IRMCOperationError if attaching virtual media failed.
    :raises: InvalidParameterValue if the validation of the
        ManagementInterface fails.
    """
    d_info = task.node.driver_internal_info
    node_state = task.node.provision_state

    if 'irmc_boot_iso' in d_info and node_state == states.ACTIVE:
        irmc_deploy.setup_vmedia_for_boot(task, d_info['irmc_boot_iso'])
        manager_utils.node_set_boot_device(task, boot_devices.CDROM)


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
        _attach_boot_iso_if_needed(task)

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


class IRMCPower(base.PowerInterface):
    """Interface for power-related actions."""

    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """
        return irmc_common.COMMON_PROPERTIES

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
            if kwargs:
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
        :raises: IRMCOperationError on an error from SCCI
        :raises: other exceptions by the node's power driver if something
                 wrong occurred during the power action.
        """
        node = task.node

        try:
            curr_state = task.driver.power.get_power_state(task)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                node.last_error = _(
                    "Failed to change power state to POWER_OFF. "
                    "Error: %(error)s") % {'error': e}
                node.target_power_state = states.NOSTATE
                node.save()

        if curr_state == states.POWER_OFF:
            node.last_error = None
            node.power_state = states.POWER_OFF
            node.target_power_state = states.NOSTATE
            node.save()
            LOG.warn(_LW("Not going to change_node_power_state because "
                         "current state is already in POWER_OFF."))
            return

        if curr_state == states.ERROR:
            # be optimistic and continue action
            LOG.warn(_LW("Driver returns ERROR power state for node %s."),
                     node.uuid)

        node.target_power_state = states.POWER_OFF
        node.last_error = None
        node.save()

        irmc_client = irmc_common.get_irmc_client(node)

        try:
            irmc_client(scci.POWER_SOFT_OFF)

        except scci.SCCIClientError as irmc_exception:
            node.last_error = _(
                "iRMC graceful_shutdown failed for node %(node_id)s "
                "to change power state to POWER_OFF. "
                "Error: %(error)s") % {'node_id': node.uuid,
                                       'error': irmc_exception}
            LOG.error(node.last_error)
            operation = _('iRMC graceful_shutdown')
            raise exception.IRMCOperationError(operation=operation,
                                               error=irmc_exception)
        else:
            node.power_state = states.POWER_OFF
            LOG.info(_LI('Successfully set node %(node)s power state to '
                         'POWER_OFF.'), {'node': node.uuid})
        finally:
            node.target_power_state = states.NOSTATE
            node.save()

    @base.passthru(['POST'])
    @task_manager.require_exclusive_lock
    def raise_nmi(self, task, **kwargs):
        """Pulse the NMI (Non Maskable Interrupt)

        :param task: a TaskManager instance containing the node to act on.
        :raises: IRMCOperationError on an error from SCCI
        """

        node = task.node
        irmc_client = irmc_common.get_irmc_client(node)

        try:
            irmc_client(scci.POWER_RAISE_NMI)

        except scci.SCCIClientError as irmc_exception:
            LOG.error(_LE("iRMC raise_nmi failed"
                          " for node %(node_id)s with error: %(error)s"),
                      {'node_id': node.uuid, 'error': irmc_exception})
            operation = _('iRMC raise_nmi')
            raise exception.IRMCOperationError(operation=operation,
                                               error=irmc_exception)


class IRMCVendorPassthru(VendorPassthru, pxe.VendorPassthru):
    """Vendor-specific interfaces for iRMC power and pxe drivers."""
    pass
