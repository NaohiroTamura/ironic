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

from ironic.common import dhcp_factory
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


"""
--#FILENAME        "SC2.MIB"
--#DESCRIPTION     "ServerControl MIB, edition 2 - for systemboard and server
                    hardware monitoring"
--#REVISION        "7.10.08"
--#VENDOR          "Fujitsu Technology Solutions"
--#TRAP-ENTERPRISE sc2Notifications
--#TRAP-VARIABLES  sc2NotificationsTrapInfo

-- Copyright (C) Fujitsu Technology Solutions 2009-2015
-- All rights reserved

-- ----------------------------------------------------------------------------
--
-- TABLE        sc2ServerTable
-- STATUS       mandatory
-- DESCRIPTION  "Table containing information about the available servers"
--
--      sc2ServerTable: 1.3.6.1.4.1.231.2.10.2.2.10.4.1
--
-- ----------------------------------------------------------------------------
sc2ServerTable OBJECT-TYPE
    SYNTAX       SEQUENCE OF Sc2Servers
    ACCESS       not-accessible
    STATUS       mandatory
    DESCRIPTION  "Table containing information about the available servers"
    ::= { sc2ServerInformation 1 }

sc2Servers OBJECT-TYPE
    SYNTAX       Sc2Servers
    ACCESS       not-accessible
    STATUS       mandatory
    DESCRIPTION  ""
    INDEX   { sc2srvUnitId }
    ::= { sc2ServerTable 1 }

Sc2Servers ::= SEQUENCE
{
    sc2srvUnitId
        INTEGER,
    sc2srvPhysicalMemory
        INTEGER,
    sc2srvLastBootResult
        INTEGER,
    sc2srvCurrentBootStatus
        INTEGER,
    sc2srvShutdownCommand
        INTEGER,
    sc2srvShutdownDelay
        INTEGER,
    sc2srvUUID
        DisplayString,
    sc2srvPhysicalMemoryOs
        INTEGER,
    sc2srvUUIDWireFormat
        DisplayString,
    sc2srvOsPlatform
        INTEGER,
    sc2srvBiosVersion
        DisplayString
}

sc2srvCurrentBootStatus OBJECT-TYPE
    SYNTAX       INTEGER
    {
        unknown(1),
        off(2),
        no-boot-cpu(3),
        self-test(4),
        setup(5),
        os-boot(6),
        diagnostic-boot(7),
        os-running(8),
        diagnostic-running(9),
        os-shutdown(10),
        diagnostic-shutdown(11),
        reset(12)
    }
    ACCESS       read-only
    STATUS       mandatory
    DESCRIPTION  "Status of the current boot"
    ::= { sc2Servers 4 }
"""
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

"""
DISMAN-EVENT-MIB

sysUpTimeInstance OBJECT IDENTIFIER ::= { sysUpTime 0 }
"""
SYSUPTIME_OID = "1.3.6.1.2.1.1.3.0"

opts = [
    # note(naohirot):
    # SNMP v3 requires iRMC firmware 7.82F or above.
    # 7.82F has been released on May 1st, 2015.
    cfg.StrOpt('snmp_version',
               default='v2c',
               help='SNMP protocol version, either "v1", "v2c" or "v3"'),
    cfg.IntOpt('snmp_port',
               default=161,
               help='SNMP port'),
    cfg.StrOpt('snmp_community',
               default='public',
               help='SNMP community. Required for versions "v1", "v2c"'),
    cfg.StrOpt('snmp_security',
               default='',
               help='SNMP security name. Required for version "v3"'),
    cfg.IntOpt('snmp_polling_interval',
               default=10,
               help='SNMP polling interval in second'),
    cfg.IntOpt('state_transition_timeout',
               default=600,
               help='State transition timeout in second'),
]

CONF.register_opts(opts, group='irmc')

VENDOR_ACTION = {
    scci.POWER_SOFT_OFF: 'graceful shutdown',
    scci.POWER_RAISE_NMI: 'raise nmi',
}


def _vendor_power_action(task, action):
    """Perform vendor specific power action.

    :param task: a TaskManager instance containing the node to act on.
    :param action: a SCCI command
    :raises: InvalidParameterValue when the wrong state is specified
             or the wrong driver info is specified.
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

    # get address of the node OS instance
    api = dhcp_factory.DHCPFactory().provider
    ip_addrs = api.get_ip_addresses(task)
    if not ip_addrs:
        node.last_error = _(
            "iRMC %(action)s failed for node %(node_id)s. "
            "Error: %(error)s") % {'action': VENDOR_ACTION[action],
                                   'node_id': node.uuid,
                                   'error': "ip address not found"}
        node.target_power_state = states.NOSTATE
        node.save()

        LOG.error(node.last_error)
        error = _("ip address not found")
        raise exception.IRMCOperationError(
            operation=VENDOR_ACTION[action], error=error)

    # check if the node OS instance is alive or shut down
    snmp_node = snmp.SNMPClient(ip_addrs[0],
                                CONF.irmc.snmp_port,
                                CONF.irmc.snmp_version,
                                CONF.irmc.snmp_community,
                                CONF.irmc.snmp_security)
    interval = CONF.irmc.snmp_polling_interval
    max_retry = int(CONF.irmc.state_transition_timeout / interval)
    try:
        for i in range(0, max_retry):
            sysuptime = snmp_node.get(SYSUPTIME_OID)
            LOG.debug("iRMC %(action)s is on going at node "
                      "%(node_id)s and %(ip_addr)s. "
                      "sysUpTime is %(sysuptime)s at %(times)s."
                      % {'action': VENDOR_ACTION[action],
                         'node_id': node.uuid,
                         'ip_addr': ip_addrs[0],
                         'sysuptime': sysuptime,
                         'times': i})
            time.sleep(interval)

        # exceeded the CONF.irmc.graceful_shutdown_timeout
        node.last_error = _(
            "iRMC %(action)s failed for node %(node_id)s. "
            "Error: OS %(ip_addr)s failed to shutdown within "
            " %(timeout)i secs.") % {
                'action': VENDOR_ACTION[action],
                'node_id': node.uuid,
                'ip_addr': ip_addrs[0],
                'timeout': 10 * max_retry}

        node.target_power_state = states.NOSTATE
        node.save()

        LOG.error(node.last_error)
        error = _('OS shutdown timeout')
        raise exception.IRMCOperationError(
            operation=VENDOR_ACTION[action], error=error)

    except exception.SNMPFailure:
        # the node OS instance has been shutdown
        LOG.debug("ServerView SNMP agent stopped at %(ip_addr)s "
                  "on %(node_id)s.",
                  {'ip_addr': ip_addrs[0],
                   'node_id': node.uuid})

    # doublely check if iRMC acknowledged the shutdown of
    # the node OS instance or not
    snmp_irmc = snmp.SNMPClient(node.driver_info['irmc_address'],
                                CONF.irmc.snmp_port,
                                CONF.irmc.snmp_version,
                                CONF.irmc.snmp_community,
                                CONF.irmc.snmp_security)
    bootstatus_value = None
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
