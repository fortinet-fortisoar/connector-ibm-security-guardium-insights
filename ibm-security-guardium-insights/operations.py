""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
from connectors.core.connector import get_logger, ConnectorError


logger = get_logger('ibm-security-guardium-insights')


class Guardium(object):
    def __init__(self, config, *args, **kwargs):
        self.encoded_token = config.get('encoded_token')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/api/v3/'.format(url)
        else:
            self.url = url + '/api/v3/'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, endpoint, method='GET', data=None, json_data=None, params=None):
        try:
            headers = {
                "Accept": "application/json",
                "Authorization": self.encoded_token
            }
            service_url = self.url + endpoint

            response = requests.request(method=method, url=service_url,
                                        headers=headers, data=data, params=params, json=json_data,
                                        verify=self.verify_ssl)

            if response.ok:
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.text
            else:
                if ('text' in str(response.headers) or 'json' in str(response.headers)) and response.json().get('message'):
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.json().get('message'))
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
            logger.error(error_msg)
            raise ConnectorError(error_msg)
        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except requests.exceptions.ConnectionError:
            logger.error('Invalid Server URL')
            raise ConnectorError('Invalid Server URL')
        except requests.exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except requests.exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            logger.error('{0}'.format(err))
            raise ConnectorError(str(err))


def _check_health(config):
    response = get_reports_list(config, params=None)
    if response:
        return True
    else:
        raise ConnectorError('Invalid Token/URL')


def check_params(params):
    parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    if parameter.get('limit'):
        if parameter.get('limit') < 1:
            raise ConnectorError('Invalid limit parameter')
    if parameter.get('offset'):
        if parameter.get('offset') < 1:
            raise ConnectorError('Invalid offset parameter')
    return parameter


def get_report_categories_list(config, params):
    igi = Guardium(config)
    if params:
        params = check_params(params)
    response = igi.make_rest_call('reports/categories', params=params)
    return response


def get_reports_list(config, params):
    igi = Guardium(config)
    if params:
        params = check_params(params)
    response = igi.make_rest_call('reports', params=params)
    return response


def get_policies_list(config, params):
    igi = Guardium(config)
    response = igi.make_rest_call('policies')
    return response


def get_policy_details(config, params):
    igi = Guardium(config)
    response = igi.make_rest_call(f"policies/{params.pop('policy_id')}/details")
    return response


def get_cases_list(config, params):
    igi = Guardium(config)
    if params:
        params = check_params(params)
    response = igi.make_rest_call('cases', params=params)
    return response


def get_tasks_list(config, params):
    igi = Guardium(config)
    if params:
        params = check_params(params)
    response = igi.make_rest_call(f"cases/{params.pop('case_id')}/tasks", params=params)
    return response


def get_groups_list(config, params):
    igi = Guardium(config)
    response = igi.make_rest_call('groups')
    return response


def get_group_members_list(config, params):
    igi = Guardium(config)
    group_id = params.get('group_id')
    if isinstance(group_id, list):
        payload = {"group_id": group_id}
    else:
        payload = {"group_id": [group_id]}
    response = igi.make_rest_call('groups/search', method='POST', json_data=payload)
    return response


def get_compliance_data(config, params):
    igi = Guardium(config)
    response = igi.make_rest_call('compliance')
    return response


def get_connections_list(config, params):
    igi = Guardium(config)
    if params:
        params = check_params(params)
    response = igi.make_rest_call('connections/accounts', params=params)
    return response


def get_datasets_list(config, params):
    igi = Guardium(config)
    if params:
        params = check_params(params)
    response = igi.make_rest_call('integrations/datasets', params=params)
    return response


def get_dataset_data(config, params):
    igi = Guardium(config)
    if params:
        params = check_params(params)
    response = igi.make_rest_call(f"integrations/datasets/{params.pop('dataset_name')}/data", params=params)
    return response


def get_notifications_list(config, params):
    igi = Guardium(config)
    if params:
        params = check_params(params)
    response = igi.make_rest_call('notifications', params=params)
    return response


def get_schedules_list(config, params):
    igi = Guardium(config)
    if params:
        params = check_params(params)
    response = igi.make_rest_call('schedules', params=params)
    return response


def get_scheduled_job_details(config, params):
    igi = Guardium(config)
    response = igi.make_rest_call(f"schedules/{params.pop('schedule_id')}/details")
    return response


operations = {
    'get_report_categories_list': get_report_categories_list,
    'get_reports_list': get_reports_list,
    'get_policies_list': get_policies_list,
    'get_policy_details': get_policy_details,
    'get_cases_list': get_cases_list,
    'get_tasks_list': get_tasks_list,
    'get_groups_list': get_groups_list,
    'get_group_members_list': get_group_members_list,
    'get_compliance_data': get_compliance_data,
    'get_connections_list': get_connections_list,
    'get_datasets_list': get_datasets_list,
    'get_dataset_data': get_dataset_data,
    'get_notifications_list': get_notifications_list,
    'get_schedules_list': get_schedules_list,
    'get_scheduled_job_details': get_scheduled_job_details
}
