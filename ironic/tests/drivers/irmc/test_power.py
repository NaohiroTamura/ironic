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
Test class for iRMC Power Driver
"""

import mock
from oslo_config import cfg

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules.irmc import common as irmc_common
from ironic.drivers.modules.irmc import deploy as irmc_deploy
from ironic.drivers.modules.irmc import power as irmc_power
from ironic.drivers.modules import pxe
from ironic.tests.conductor import utils as mgr_utils
from ironic.tests.db import base as db_base
from ironic.tests.db import utils as db_utils
from ironic.tests.objects import utils as obj_utils

INFO_DICT = db_utils.get_test_irmc_info()
CONF = cfg.CONF


@mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                   autospec=True)
class IRMCPowerInternalMethodsTestCase(db_base.DbTestCase):

    def setUp(self):
        super(IRMCPowerInternalMethodsTestCase, self).setUp()
        mgr_utils.mock_the_extension_manager(driver='fake_irmc')
        driver_info = INFO_DICT
        self.node = db_utils.create_test_node(
            driver='fake_irmc',
            driver_info=driver_info,
            instance_uuid='instance_uuid_123')

    @mock.patch.object(irmc_power, '_attach_boot_iso_if_needed')
    def test__set_power_state_power_on_ok(
            self,
            _attach_boot_iso_if_needed_mock,
            get_irmc_client_mock):
        irmc_client = get_irmc_client_mock.return_value
        target_state = states.POWER_ON
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            irmc_power._set_power_state(task, target_state)
            _attach_boot_iso_if_needed_mock.assert_called_once_with(task)
        irmc_client.assert_called_once_with(irmc_power.scci.POWER_ON)

    def test__set_power_state_power_off_ok(self,
                                           get_irmc_client_mock):
        irmc_client = get_irmc_client_mock.return_value
        target_state = states.POWER_OFF
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            irmc_power._set_power_state(task, target_state)
        irmc_client.assert_called_once_with(irmc_power.scci.POWER_OFF)

    @mock.patch.object(irmc_power, '_attach_boot_iso_if_needed')
    def test__set_power_state_power_reboot_ok(
            self,
            _attach_boot_iso_if_needed_mock,
            get_irmc_client_mock):
        irmc_client = get_irmc_client_mock.return_value
        target_state = states.REBOOT
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            irmc_power._set_power_state(task, target_state)
            _attach_boot_iso_if_needed_mock.assert_called_once_with(task)
        irmc_client.assert_called_once_with(irmc_power.scci.POWER_RESET)

    def test__set_power_state_invalid_target_state(self,
                                                   get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.InvalidParameterValue,
                              irmc_power._set_power_state,
                              task,
                              states.ERROR)

    def test__set_power_state_scci_exception(self,
                                             get_irmc_client_mock):
        irmc_client = get_irmc_client_mock.return_value
        irmc_client.side_effect = Exception()
        irmc_power.scci.SCCIClientError = Exception

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.IRMCOperationError,
                              irmc_power._set_power_state,
                              task,
                              states.POWER_ON)

    @mock.patch.object(manager_utils, 'node_set_boot_device', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_deploy, 'setup_vmedia_for_boot', spec_set=True,
                       autospec=True)
    def test__attach_boot_iso_if_needed(
            self,
            setup_vmedia_mock,
            set_boot_device_mock,
            get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.provision_state = states.ACTIVE
            task.node.driver_internal_info['irmc_boot_iso'] = 'boot-iso'
            irmc_power._attach_boot_iso_if_needed(task)
            setup_vmedia_mock.assert_called_once_with(task, 'boot-iso')
            set_boot_device_mock.assert_called_once_with(
                task, boot_devices.CDROM)

    @mock.patch.object(manager_utils, 'node_set_boot_device', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_deploy, 'setup_vmedia_for_boot', spec_set=True,
                       autospec=True)
    def test__attach_boot_iso_if_needed_on_rebuild(
            self,
            setup_vmedia_mock,
            set_boot_device_mock,
            get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.provision_state = states.DEPLOYING
            task.node.driver_internal_info['irmc_boot_iso'] = 'boot-iso'
            irmc_power._attach_boot_iso_if_needed(task)
            self.assertFalse(setup_vmedia_mock.called)
            self.assertFalse(set_boot_device_mock.called)


class IRMCPowerTestCase(db_base.DbTestCase):
    def setUp(self):
        super(IRMCPowerTestCase, self).setUp()
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

    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate(self, mock_drvinfo):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.driver.power.validate(task)
            mock_drvinfo.assert_called_once_with(task.node)

    @mock.patch.object(irmc_common, 'parse_driver_info', spec_set=True,
                       autospec=True)
    def test_validate_fail(self, mock_drvinfo):
        side_effect = iter([exception.InvalidParameterValue("Invalid Input")])
        mock_drvinfo.side_effect = side_effect
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.power.validate,
                              task)

    @mock.patch('ironic.drivers.modules.irmc.power.ipmitool.IPMIPower',
                spec_set=True, autospec=True)
    def test_get_power_state(self, mock_IPMIPower):
        ipmi_power = mock_IPMIPower.return_value
        ipmi_power.get_power_state.return_value = states.POWER_ON
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertEqual(states.POWER_ON,
                             task.driver.power.get_power_state(task))
            ipmi_power.get_power_state.assert_called_once_with(task)

    @mock.patch.object(irmc_power, '_set_power_state', spec_set=True,
                       autospec=True)
    def test_set_power_state(self, mock_set_power):
        mock_set_power.return_value = states.POWER_ON
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.power.set_power_state(task, states.POWER_ON)
        mock_set_power.assert_called_once_with(task, states.POWER_ON)

    @mock.patch.object(irmc_power, '_set_power_state', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test_reboot_reboot(self, mock_get_power, mock_set_power):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            mock_get_power.return_value = states.POWER_ON
            task.driver.power.reboot(task)
            mock_get_power.assert_called_once_with(
                task.driver.power, task)
        mock_set_power.assert_called_once_with(task, states.REBOOT)

    @mock.patch.object(irmc_power, '_set_power_state', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test_reboot_power_on(self, mock_get_power, mock_set_power):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            mock_get_power.return_value = states.POWER_OFF
            task.driver.power.reboot(task)
            mock_get_power.assert_called_once_with(
                task.driver.power, task)
        mock_set_power.assert_called_once_with(task, states.POWER_ON)


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
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
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
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
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
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
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
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
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
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
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
            vendor = irmc_power.IRMCPxeVendorPassthru()
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
            vendor = irmc_power.IRMCIscsiVendorPassthru()
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
            vendor = irmc_power.IRMCPxeVendorPassthru()
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
            vendor = irmc_power.IRMCIscsiVendorPassthru()
            result = vendor.validate(
                task, method='pass_bootloader_install_info', foo='bar')
            self.assertFalse(mock_drvinfo.called)
            validate_mock.assert_called_once_with(
                vendor, task, 'pass_bootloader_install_info', foo='bar')
            self.assertIsNone(result)

    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(irmc_power.IRMCPower, 'get_power_state', spec_set=True,
                       autospec=True)
    def test_graceful_shutdown(self,
                               get_power_state_mock,
                               get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                result = vendor.graceful_shutdown(task)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_power.scci.POWER_SOFT_OFF, async=False)
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
    def test_graceful_shutdown_get_power_state_fail(self,
                                                    get_power_state_mock,
                                                    get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
                get_power_state_mock.side_effect = Exception()
                irmc_client = get_irmc_client_mock.return_value
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None
                self.assertRaises(exception.VendorPassthruException,
                                  vendor.graceful_shutdown,
                                  task)

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
    def test_graceful_shutdown_already_powered_off(self,
                                                   get_power_state_mock,
                                                   get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                result = vendor.graceful_shutdown(task)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_power.scci.POWER_SOFT_OFF, async=False)
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
    def test_graceful_shutdown_curr_state_error(self,
                                                get_power_state_mock,
                                                get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.ERROR
                irmc_client = get_irmc_client_mock.return_value
                result = vendor.graceful_shutdown(task)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_power.scci.POWER_SOFT_OFF, async=False)
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
    def test_graceful_shutdown_irmc_client_fail(self,
                                                get_power_state_mock,
                                                get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
                get_power_state_mock.return_value = states.POWER_ON
                irmc_client = get_irmc_client_mock.return_value
                irmc_client.side_effect = Exception()
                irmc_power.scci.SCCIClientError = Exception
                task.node['power_state'] = states.POWER_ON
                task.node['last_error'] = None
                self.assertRaises(exception.IRMCOperationError,
                                  vendor.graceful_shutdown,
                                  task)

                get_power_state_mock.assert_called_once_with(
                    task.driver.power, task)
                irmc_client.assert_called_once_with(
                    irmc_power.scci.POWER_SOFT_OFF, async=False)
                self.assertEqual(states.POWER_ON, task.node['power_state'])
                self.assertIsNone(task.node['target_power_state'])
                self.assertIsNotNone(task.node['last_error'])
                get_power_state_mock.reset_mock()
                irmc_client.reset_mock()

    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    def test_raise_nmi(self, get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
                irmc_client = get_irmc_client_mock.return_value
                result = vendor.raise_nmi(task)

                irmc_client.assert_called_once_with(
                    irmc_power.scci.POWER_RAISE_NMI)
                self.assertIsNone(result)
                irmc_client.reset_mock()

    @mock.patch.object(irmc_common, 'get_irmc_client', spec_set=True,
                       autospec=True)
    def test_raise_nmi_irmc_client_fail(self, get_irmc_client_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            for vendor in (irmc_power.IRMCPxeVendorPassthru(),
                           irmc_power.IRMCIscsiVendorPassthru(),
                           irmc_power.IRMCAgentVendorPassthru()):
                irmc_client = get_irmc_client_mock.return_value
                irmc_client.side_effect = Exception()
                irmc_power.scci.SCCIClientError = Exception

                self.assertRaises(exception.IRMCOperationError,
                                  vendor.raise_nmi,
                                  task)

                irmc_client.assert_called_once_with(
                    irmc_power.scci.POWER_RAISE_NMI)
                irmc_client.reset_mock()
