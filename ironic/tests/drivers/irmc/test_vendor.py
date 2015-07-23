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
Test class for iRMC Vendor Driver
"""
import time

import mock

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers.modules.irmc import common as irmc_common
from ironic.drivers.modules.irmc import deploy as irmc_deploy
from ironic.drivers.modules.irmc import power as irmc_power
from ironic.drivers.modules.irmc import vendor as irmc_vendor
from ironic.drivers.modules import pxe
from ironic.tests.conductor import utils as mgr_utils
from ironic.tests.db import base as db_base
from ironic.tests.db import utils as db_utils
from ironic.tests.objects import utils as obj_utils

INFO_DICT = db_utils.get_test_irmc_info()


class IRMCVendorPassthruPrivateMethodsTestCase(db_base.DbTestCase):
    def setUp(self):
        super(IRMCVendorPassthruPrivateMethodsTestCase, self).setUp()
        driver_info = INFO_DICT
        mgr_utils.mock_the_extension_manager(driver="fake_irmc")
        self.node = obj_utils.create_test_node(self.context,
                                               driver='fake_irmc',
                                               driver_info=driver_info)

    @mock.patch.object(time, 'sleep', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.snmp.SNMPClient',
                spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.dhcp_factory.DHCPFactory',
                spec_set=True, autospec=True)
    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_soft_power_off(self,
                                                 get_power_state_mock,
                                                 get_irmc_client_mock,
                                                 dhcp_factory_mock,
                                                 snmpclient_mock,
                                                 sleep_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info = {"irmc_address": "1.2.3.4"}
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                dhcp_factory_mock.return_value = mock.Mock(
                    **{'provider.get_ip_addresses.return_value': ["5.6.7.8"]})
                snmpclient_mock.side_effect = [
                    mock.Mock(**{'get.side_effect': exception.SNMPFailure(
                        operation="GET", error="error")}),
                    mock.Mock(**{'get.return_value': 2})]

                result = irmc_vendor._vendor_power_action(
                    task, irmc_vendor.scci.POWER_SOFT_OFF)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_vendor.scci.POWER_SOFT_OFF)
                (dhcp_factory_mock.return_value.provider
                 .get_ip_addresses.assert_called_once_with)(task)
                snmpclient_mock.assert_has_calls(
                    [mock.call("5.6.7.8", 161, "v2c", "public", ''),
                     mock.call("1.2.3.4", 161, "v2c", "public", '')])
                self.assertIsNone(result)
                self.assertEqual(states.POWER_OFF, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()
                dhcp_factory_mock.reset_mock()
                snmpclient_mock.reset_mock()

    @mock.patch.object(time, 'sleep', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.snmp.SNMPClient',
                spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.dhcp_factory.DHCPFactory',
                spec_set=True, autospec=True)
    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_power_raise_nmi(self,
                                                  get_power_state_mock,
                                                  get_irmc_client_mock,
                                                  dhcp_factory_mock,
                                                  snmpclient_mock,
                                                  sleep_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info = {"irmc_address": "1.2.3.4"}
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                dhcp_factory_mock.return_value = mock.Mock(
                    **{'provider.get_ip_addresses.return_value': ["5.6.7.8"]})
                snmpclient_mock.side_effect = [
                    mock.Mock(**{'get.side_effect': exception.SNMPFailure(
                        operation="GET", error="error")}),
                    mock.Mock(**{'get.return_value': 8})]

                result = irmc_vendor._vendor_power_action(
                    task, irmc_vendor.scci.POWER_RAISE_NMI)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_vendor.scci.POWER_RAISE_NMI)
                (dhcp_factory_mock.return_value.provider
                 .get_ip_addresses.assert_called_once_with)(task)
                snmpclient_mock.assert_has_calls(
                    [mock.call("5.6.7.8", 161, "v2c", "public", ''),
                     mock.call("1.2.3.4", 161, "v2c", "public", '')])
                self.assertIsNone(result)
                self.assertEqual(states.POWER_ON, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()
                dhcp_factory_mock.reset_mock()
                snmpclient_mock.reset_mock()

    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_get_power_state_fail(self,
                                                       get_power_state_mock,
                                                       get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.side_effect = (
                    exception.InvalidParameterValue("fake error"))
                irmc_client = get_irmc_client_mock.return_value
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None

                self.assertRaises(exception.InvalidParameterValue,
                                  irmc_vendor._vendor_power_action,
                                  task,
                                  irmc_vendor.scci.POWER_SOFT_OFF)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                self.assertFalse(irmc_client.called)
                self.assertEqual(states.POWER_ON, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNotNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()

    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_already_powered_off(self,
                                                      get_power_state_mock,
                                                      get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_OFF
                irmc_client = get_irmc_client_mock.return_value
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None

                result = irmc_vendor._vendor_power_action(
                    task, irmc_vendor.scci.POWER_SOFT_OFF)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                self.assertFalse(irmc_client.called)
                self.assertIsNone(result)
                self.assertEqual(states.POWER_OFF, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()

    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_curr_state_error(self,
                                                   get_power_state_mock,
                                                   get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info = {"irmc_address": "1.2.3.4"}
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.ERROR
                irmc_client = get_irmc_client_mock.return_value
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None

                self.assertRaises(exception.PowerStateFailure,
                                  irmc_vendor._vendor_power_action,
                                  task,
                                  irmc_vendor.scci.POWER_SOFT_OFF)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                self.assertFalse(irmc_client.called)
                self.assertEqual(states.POWER_ON, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNotNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()

    @mock.patch('ironic.drivers.modules.irmc.vendor.dhcp_factory.DHCPFactory',
                spec_set=True, autospec=True)
    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_irmc_client_fail(self,
                                                   get_power_state_mock,
                                                   get_irmc_client_mock,
                                                   dhcp_factory_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                irmc_client.side_effect = Exception()
                irmc_vendor.scci.SCCIClientError = Exception
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None

                self.assertRaises(exception.IRMCOperationError,
                                  irmc_vendor._vendor_power_action,
                                  task,
                                  irmc_vendor.scci.POWER_SOFT_OFF)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_vendor.scci.POWER_SOFT_OFF)
                self.assertFalse(dhcp_factory_mock.called)
                self.assertEqual(states.POWER_ON, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNotNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()
                dhcp_factory_mock.reset_mock()

    @mock.patch('ironic.drivers.modules.irmc.vendor.snmp.SNMPClient',
                spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.dhcp_factory.DHCPFactory',
                spec_set=True, autospec=True)
    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_dhcp_ip_none(self,
                                               get_power_state_mock,
                                               get_irmc_client_mock,
                                               dhcp_factory_mock,
                                               snmpclient_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                dhcp_factory_mock.return_value = mock.Mock(
                    **{'provider.get_ip_addresses.return_value': []})
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None

                self.assertRaises(exception.IRMCOperationError,
                                  irmc_vendor._vendor_power_action,
                                  task,
                                  irmc_vendor.scci.POWER_SOFT_OFF)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_vendor.scci.POWER_SOFT_OFF)
                (dhcp_factory_mock.return_value.provider
                 .get_ip_addresses.assert_called_once_with)(task)
                self.assertFalse(snmpclient_mock.called)
                self.assertEqual(states.POWER_ON, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNotNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()
                dhcp_factory_mock.reset_mock()

    @mock.patch.object(time, 'sleep', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.snmp.SNMPClient',
                spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.dhcp_factory.DHCPFactory',
                spec_set=True, autospec=True)
    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_os_snmp_timeout(self,
                                                  get_power_state_mock,
                                                  get_irmc_client_mock,
                                                  dhcp_factory_mock,
                                                  snmpclient_mock,
                                                  sleep_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info = {"irmc_address": "1.2.3.4"}
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                dhcp_factory_mock.return_value = mock.Mock(
                    **{'provider.get_ip_addresses.return_value': ["5.6.7.8"]})
                snmpclient_mock.side_effect = [
                    mock.Mock(**{'get.return_value': 1}),
                    mock.Mock(**{'get.return_value': 2})]
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None

                self.assertRaises(exception.IRMCOperationError,
                                  irmc_vendor._vendor_power_action,
                                  task,
                                  irmc_vendor.scci.POWER_SOFT_OFF)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_vendor.scci.POWER_SOFT_OFF)
                (dhcp_factory_mock.return_value.provider
                 .get_ip_addresses.assert_called_once_with)(task)
                snmpclient_mock.assert_called_once_with(
                    "5.6.7.8", 161, "v2c", "public", '')
                self.assertEqual(states.POWER_ON, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNotNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()
                dhcp_factory_mock.reset_mock()
                snmpclient_mock.reset_mock()

    @mock.patch.object(time, 'sleep', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.snmp.SNMPClient',
                spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.dhcp_factory.DHCPFactory',
                spec_set=True, autospec=True)
    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_irmc_snmp_fail(self,
                                                 get_power_state_mock,
                                                 get_irmc_client_mock,
                                                 dhcp_factory_mock,
                                                 snmpclient_mock,
                                                 sleep_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info = {"irmc_address": "1.2.3.4"}
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                dhcp_factory_mock.return_value = mock.Mock(
                    **{'provider.get_ip_addresses.return_value': ["5.6.7.8"]})
                snmpclient_mock.side_effect = [
                    mock.Mock(**{'get.side_effect': exception.SNMPFailure(
                        operation="GET", error="error")}),
                    mock.Mock(**{'get.side_effect': exception.SNMPFailure(
                        operation="GET", error="error")})]
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None

                self.assertRaises(exception.IRMCOperationError,
                                  irmc_vendor._vendor_power_action,
                                  task,
                                  irmc_vendor.scci.POWER_SOFT_OFF)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_vendor.scci.POWER_SOFT_OFF)
                (dhcp_factory_mock.return_value.provider
                 .get_ip_addresses.assert_called_once_with)(task)
                snmpclient_mock.assert_has_calls(
                    [mock.call("5.6.7.8", 161, "v2c", "public", ''),
                     mock.call("1.2.3.4", 161, "v2c", "public", '')])
                self.assertEqual(states.POWER_ON, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNotNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()
                dhcp_factory_mock.reset_mock()
                snmpclient_mock.reset_mock()

    @mock.patch.object(time, 'sleep', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.snmp.SNMPClient',
                spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.irmc.vendor.dhcp_factory.DHCPFactory',
                spec_set=True, autospec=True)
    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test__vendor_power_action_irmc_snmp_timeout(self,
                                                    get_power_state_mock,
                                                    get_irmc_client_mock,
                                                    dhcp_factory_mock,
                                                    snmpclient_mock,
                                                    sleep_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info = {"irmc_address": "1.2.3.4"}
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                dhcp_factory_mock.return_value = mock.Mock(
                    **{'provider.get_ip_addresses.return_value': ["5.6.7.8"]})
                snmpclient_mock.side_effect = [
                    mock.Mock(**{'get.side_effect': exception.SNMPFailure(
                        operation="GET", error="error")}),
                    mock.Mock(**{'get.return_value': 8})]
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None

                self.assertRaises(exception.IRMCOperationError,
                                  irmc_vendor._vendor_power_action,
                                  task,
                                  irmc_vendor.scci.POWER_SOFT_OFF)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_vendor.scci.POWER_SOFT_OFF)
                (dhcp_factory_mock.return_value.provider
                 .get_ip_addresses.assert_called_once_with)(task)
                snmpclient_mock.assert_has_calls(
                    [mock.call("5.6.7.8", 161, "v2c", "public", ''),
                     mock.call("1.2.3.4", 161, "v2c", "public", '')])
                self.assertEqual(states.POWER_ON, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNotNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()
                dhcp_factory_mock.reset_mock()
                snmpclient_mock.reset_mock()


class VendorPassthruTestCase(db_base.DbTestCase):

    def setUp(self):
        super(VendorPassthruTestCase, self).setUp()
        driver_info = INFO_DICT
        mgr_utils.mock_the_extension_manager(driver="fake_irmc")
        self.node = obj_utils.create_test_node(self.context,
                                               driver='fake_irmc',
                                               driver_info=driver_info)

    def test_get_properties(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            properties = task.driver.get_properties()
            for prop in irmc_common.COMMON_PROPERTIES:
                self.assertIn(prop, properties)


class IRMCVendorPassthruTestCase(db_base.DbTestCase):

    def setUp(self):
        super(IRMCVendorPassthruTestCase, self).setUp()
        driver_info = INFO_DICT
        mgr_utils.mock_the_extension_manager(driver="fake_irmc")
        self.node = obj_utils.create_test_node(self.context,
                                               driver='fake_irmc',
                                               driver_info=driver_info)

    def test_get_properties(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            properties = task.driver.get_properties()
            irmc_pxe_prop = dict(list(irmc_common.COMMON_PROPERTIES.items())
                                 + list(pxe.COMMON_PROPERTIES.items()))
            for prop in irmc_pxe_prop:
                self.assertIn(prop, properties)

    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_graceful_shutdown(self, mock_drvinfo):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                result = vendor.validate(
                    task, method='graceful_shutdown', http_method='POST')
                mock_drvinfo.assert_called_once_with(task.node)
                self.assertIsNone(result)
                mock_drvinfo.reset_mock()

    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_raise_nmi(self, mock_drvinfo):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                result = vendor.validate(
                    task, method='raise_nmi', http_method='POST')
                mock_drvinfo.assert_called_once_with(task.node)
                self.assertIsNone(result)
                mock_drvinfo.reset_mock()

    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_unknown(self, mock_drvinfo):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                result = vendor.validate(
                    task, method='unknown', http_method='POST')
                self.assertFalse(mock_drvinfo.called)
                self.assertIsNone(result)
                mock_drvinfo.reset_mock()

    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_graceful_shutdown_with_param(self, mock_drvinfo):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                self.assertRaises(exception.InvalidParameterValue,
                                  vendor.validate,
                                  task,
                                  method='graceful_shutdown',
                                  foo='bar')
                self.assertFalse(mock_drvinfo.called)
                mock_drvinfo.reset_mock()

    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_raise_nmi_with_param(self, mock_drvinfo):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                self.assertRaises(exception.InvalidParameterValue,
                                  vendor.validate,
                                  task,
                                  method='raise_nmi',
                                  foo='bar')
                self.assertFalse(mock_drvinfo.called)
                mock_drvinfo.reset_mock()

    @mock.patch.object(pxe.VendorPassthru, 'validate', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_pxe_pass_deploy_info(self, mock_drvinfo, validate_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            vendor = irmc_vendor.IRMCPxeVendorPassthru()
            result = vendor.validate(
                task, method='pass_deploy_info', foo='bar')
            self.assertFalse(mock_drvinfo.called)
            validate_mock.assert_called_once_with(
                vendor, task, 'pass_deploy_info', foo='bar')
            self.assertIsNone(result)

    @mock.patch.object(irmc_deploy.VendorPassthru, 'validate',
                       spec_set=True, autospec=True)
    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_irmc_pass_deploy_info(self, mock_drvinfo, validate_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            vendor = irmc_vendor.IRMCIscsiVendorPassthru()
            result = vendor.validate(
                task, method='pass_deploy_info', foo='bar')
            self.assertFalse(mock_drvinfo.called)
            validate_mock.assert_called_once_with(
                vendor, task, 'pass_deploy_info', foo='bar')
            self.assertIsNone(result)

    @mock.patch.object(pxe.VendorPassthru, 'validate', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_pxe_pass_bootloader_install_info(self, mock_drvinfo,
                                                       validate_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            vendor = irmc_vendor.IRMCPxeVendorPassthru()
            result = vendor.validate(
                task, method='pass_bootloader_install_info', foo='bar')
            self.assertFalse(mock_drvinfo.called)
            validate_mock.assert_called_once_with(
                vendor, task, 'pass_bootloader_install_info', foo='bar')
            self.assertIsNone(result)

    @mock.patch.object(irmc_deploy.VendorPassthru, 'validate',
                       spec_set=True, autospec=True)
    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_irmc_pass_bootloader_install_info(self, mock_drvinfo,
                                                        validate_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            vendor = irmc_vendor.IRMCIscsiVendorPassthru()
            result = vendor.validate(
                task, method='pass_bootloader_install_info', foo='bar')
            self.assertFalse(mock_drvinfo.called)
            validate_mock.assert_called_once_with(
                vendor, task, 'pass_bootloader_install_info', foo='bar')
            self.assertIsNone(result)

    @mock.patch.object(irmc_vendor, '_vendor_power_action', spec_set=True,
                       autospec=True)
    def test_graceful_shutdown(self, _vendor_power_action_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                vendor.graceful_shutdown(task)

                _vendor_power_action_mock.assert_called_once_with(
                    task, irmc_vendor.scci.POWER_SOFT_OFF)
                _vendor_power_action_mock.reset_mock()

    @mock.patch.object(irmc_vendor, '_vendor_power_action', spec_set=True,
                       autospec=True)
    def test_raise_nmi(self, _vendor_power_action_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_vendor.IRMCPxeVendorPassthru(),
                           irmc_vendor.IRMCIscsiVendorPassthru(),
                           irmc_vendor.IRMCAgentVendorPassthru()):
                vendor.raise_nmi(task)

                _vendor_power_action_mock.assert_called_once_with(
                    task, irmc_vendor.scci.POWER_RAISE_NMI)
                _vendor_power_action_mock.reset_mock()
