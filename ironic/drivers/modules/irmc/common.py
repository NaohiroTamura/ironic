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
Common functionalities shared between different iRMC modules.
"""

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from ironic.common import exception
from ironic.common.i18n import _

scci = importutils.try_import('scciclient.irmc.scci')

opts = [
    cfg.IntOpt('port',
               default=443,
               help=_('Port to be used for iRMC operations, either 80 or '
                      '443')),
    cfg.StrOpt('auth_method',
               default='basic',
               help=_('Authentication method to be used for iRMC operations, '
                      'either "basic" or "digest"')),
    cfg.IntOpt('client_timeout',
               default=60,
               help=_('Timeout (in seconds) for iRMC operations')),
    cfg.StrOpt('sensor_method',
               default='ipmitool',
               help=_('Sensor data retrieval method, either '
                      '"ipmitool" or "scci"')),
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

CONF = cfg.CONF
CONF.register_opts(opts, group='irmc')

LOG = logging.getLogger(__name__)

REQUIRED_PROPERTIES = {
    'irmc_address': _("IP address or hostname of the iRMC. Required."),
    'irmc_username': _("Username for the iRMC with administrator privileges. "
                       "Required."),
    'irmc_password': _("Password for irmc_username. Required."),
}
OPTIONAL_PROPERTIES = {
    'irmc_port': _("Port to be used for iRMC operations; either 80 or 443. "
                   "The default value is 443. Optional."),
    'irmc_auth_method': _("Authentication method for iRMC operations; "
                          "either 'basic' or 'digest'. The default value is "
                          "'basic'. Optional."),
    'irmc_client_timeout': _("Timeout (in seconds) for iRMC operations. "
                             "The default value is 60. Optional."),
    'irmc_sensor_method': _("Sensor data retrieval method; either "
                            "'ipmitool' or 'scci'. The default value is "
                            "'ipmitool'. Optional."),
}

COMMON_PROPERTIES = REQUIRED_PROPERTIES.copy()
COMMON_PROPERTIES.update(OPTIONAL_PROPERTIES)


def parse_driver_info(node):
    """Gets the specific Node driver info.

    This method validates whether the 'driver_info' property of the
    supplied node contains the required information for this driver.

    :param node: An ironic node object.
    :returns: A dict containing information from driver_info
        and default values.
    :raises: InvalidParameterValue if invalid value is contained
        in the 'driver_info' property.
    :raises: MissingParameterValue if some mandatory key is missing
        in the 'driver_info' property.
    """
    info = node.driver_info
    missing_info = [key for key in REQUIRED_PROPERTIES if not info.get(key)]
    if missing_info:
        raise exception.MissingParameterValue(_(
            "Missing the following iRMC parameters in node's"
            " driver_info: %s.") % missing_info)

    req = {key: value for key, value in info.items()
           if key in REQUIRED_PROPERTIES}
    # corresponding config names don't have 'irmc_' prefix
    opt = {param: info.get(param, CONF.irmc.get(param[len('irmc_'):]))
           for param in OPTIONAL_PROPERTIES}
    d_info = dict(list(req.items()) + list(opt.items()))

    error_msgs = []
    if (d_info['irmc_auth_method'].lower() not in ('basic', 'digest')):
        error_msgs.append(
            _("'irmc_auth_method' has unsupported value."))
    if d_info['irmc_port'] not in (80, 443):
        error_msgs.append(
            _("'irmc_port' has unsupported value."))
    if not isinstance(d_info['irmc_client_timeout'], int):
        error_msgs.append(
            _("'irmc_client_timeout' is not integer type."))
    if d_info['irmc_sensor_method'].lower() not in ('ipmitool', 'scci'):
        error_msgs.append(
            _("'irmc_sensor_method' has unsupported value."))
    if error_msgs:
        msg = (_("The following type errors were encountered while parsing "
                 "driver_info:\n%s") % "\n".join(error_msgs))
        raise exception.InvalidParameterValue(msg)

    return d_info


def get_irmc_client(node):
    """Gets an iRMC SCCI client.

    Given an ironic node object, this method gives back a iRMC SCCI client
    to do operations on the iRMC.

    :param node: An ironic node object.
    :returns: scci_cmd partial function which takes a SCCI command param.
    :raises: InvalidParameterValue on invalid inputs.
    :raises: MissingParameterValue if some mandatory information
        is missing on the node
    """
    driver_info = parse_driver_info(node)

    scci_client = scci.get_client(
        driver_info['irmc_address'],
        driver_info['irmc_username'],
        driver_info['irmc_password'],
        port=driver_info['irmc_port'],
        auth_method=driver_info['irmc_auth_method'],
        client_timeout=driver_info['irmc_client_timeout'])
    return scci_client


def update_ipmi_properties(task):
    """Update ipmi properties to node driver_info

    :param task: A task from TaskManager.
    """
    node = task.node
    info = node.driver_info

    # updating ipmi credentials
    info['ipmi_address'] = info.get('irmc_address')
    info['ipmi_username'] = info.get('irmc_username')
    info['ipmi_password'] = info.get('irmc_password')

    # saving ipmi credentials to task object
    task.node.driver_info = info


def get_irmc_report(node):
    """Gets iRMC SCCI report.

    Given an ironic node object, this method gives back a iRMC SCCI report.

    :param node: An ironic node object.
    :returns: A xml.etree.ElementTree object.
    :raises: InvalidParameterValue on invalid inputs.
    :raises: MissingParameterValue if some mandatory information
        is missing on the node.
    :raises: scci.SCCIInvalidInputError if required parameters are invalid.
    :raises: scci.SCCIClientError if SCCI failed.
    """
    driver_info = parse_driver_info(node)

    return scci.get_report(
        driver_info['irmc_address'],
        driver_info['irmc_username'],
        driver_info['irmc_password'],
        port=driver_info['irmc_port'],
        auth_method=driver_info['irmc_auth_method'],
        client_timeout=driver_info['irmc_client_timeout'])
