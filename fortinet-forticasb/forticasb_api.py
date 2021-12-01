"""
FortiCASB REST Client implementation
"""

import requests
import logging
import arrow
import logging.handlers
from time import gmtime, strftime
import jmespath
from requests_toolbelt.utils import dump


class FortiCasbCS(object):
    ''' Main API Client Class '''

    def __init__(self,
                 base_url,                 
                 forticasb_credentials,
                 verify_ssl=False,
                 logger=None
                 ):
        self.forticasb_logging = self.set_logger(logger)
        self.forticasb_credentials = "Basic " + forticasb_credentials
        self.base_url = base_url + '/api/v1'
        self.verify_ssl = self.set_verify_ssl(verify_ssl)
        self.token_expires_at = 0
        self.request_timeout = 20
        self.headers = {
            'user-agent': 'autobot',
            'Authorization': self.forticasb_credentials
        }
        self.login()
                

    def set_logger(self, logger):
        if logger is None:
            logging.basicConfig(level=logging.DEBUG)
            new_logger = logging.getLogger('API_Logger')
            return new_logger
        else:
            return logger

    def set_verify_ssl(self, ssl_status):
        if isinstance(ssl_status,str):
            ssl_status.lower()
        if ssl_status in ["true", True]:
            return True
        elif ssl_status in ["false", False]:
            return False
        else:
            return True


    def login(self):
        ''' Fetches bearer access token'''

        try:
            response = requests.post(
            self.base_url+'/auth/credentials/token/',
            headers=self.headers,
            data={"grant_type": "client_credentials"},
            verify=self.verify_ssl,
            timeout=self.request_timeout
            )        
            self.forticasb_logging.debug('Authentication Request:\n{}'.format(dump.dump_all(response).decode('utf-8')))

            if response and response.status_code == 200:
                json_response = response.json()
                self.headers['Authorization'] = 'Bearer ' + json_response['access_token']
                self.headers.update({'companyId' : json_response['companyId']})
                self.headers.update({'Content-Type' : 'application/json'})
                self.token_expires_at = json_response['expires']
                self.forticasb_logging.info('Authentication successful. it will be valid until: {}'.format(self.token_expires_at))

            else:
                raise Exception('Failed Authentication')

        except Exception as e:
            self.forticasb_logging.exception('Failed to open a session')
            raise Exception('Failed to open a session: {}'.format(e))


    def make_rest_call(self, endpoint, params=None, data=None, method='GET',debug=True):
        '''make_rest_call'''

        url = '{0}{1}'.format(self.base_url, endpoint)

        if debug:
            self.forticasb_logging.debug('Request URL {}\n Headers:{}'.format(url,self.headers))

        try:
            response = requests.request(method,
                                        url,
                                        json=data,
                                        headers=self.headers,
                                        verify=self.verify_ssl,
                                        params=params,
                                        timeout=self.request_timeout
                                        )
            
            if debug:
                self.forticasb_logging.debug('REQUESTS_DUMP:\n{}'.format(dump.dump_all(response).decode('utf-8')))
            if response.status_code in [200,201]:
                return {'Status':'Success','data':response.json()}
            else:
                return_data = {
                        'Status': 'Failure',
                        'data': {
                                'Server Response':response.content,
                                'Status Code': str(response.status_code)
                        }
                }
                self.forticasb_logging.exception(return_data)
                return return_data

        except Exception as e:
            self.forticasb_logging.exception("Request Failed: {}".format(e))
            raise Exception("Request Failed: {}".format(e))

    def get_resource_map(self):
        '''Get the user and account basic information from FortiCASB'''
        try:
            response = self.make_rest_call('/resourceURLMap')
            if response['Status'] == 'Success':
                return response
            else:
                raise Exception(response)
        except Exception as e:
            self.forticasb_logging.exception(e)
            raise Exception(e)

    def get_business_unit_ids(self):
        '''List all available Business Units IDs'''
        try:
            bu_list = []
            resource_map = self.get_resource_map()
            if resource_map['Status'] == 'Success':
                for resource in resource_map['data']:
                    if len(resource['buMapSet']) > 0:
                        bu_list += jmespath.search('buMapSet[].buId', resource)
                        return list(dict.fromkeys(bu_list))
            else:
                raise Exception(resource_map)
    
        except Exception as e:
            self.forticasb_logging.exception(e)
            raise Exception(e)

    def _get_dashboard(self,business_unit_id,start_time,end_time,dashboard):
        ''' Get Dashboard'''
        try:
            payload = {"startTime":start_time,"endTime":end_time}
            self.headers.update({'buId':str(business_unit_id)})
            self.headers.update({'timeZone':strftime("%z", gmtime())})
            response = self.make_rest_call('/dashboard/'+dashboard,
                                      method='POST',
                                      data=payload
                                      )
            if response['Status'] == 'Success':
                return response
            else:
                raise Exception(response)

        except Exception as e:
            self.forticasb_logging.exception(e)
            raise Exception(e)


    def get_dashboard_risk(self,business_unit_id,start_time,end_time):
        '''Get all risk trend data of all monitoring accounts in the business unit'''

        return self._get_dashboard(business_unit_id,start_time,end_time,'risk')


    def get_dashboard_usage(self,business_unit_id,start_time,end_time):
        '''Get all activity usage trend data of all the monitoring cloud accounts in the business unit'''

        return self._get_dashboard(business_unit_id,start_time,end_time,'usage')

      
    def get_bu_services(self,business_unit_id,start_time,end_time):
        '''Get a list of services for a business Unit'''
        try:      
            dashboard_usage = self.get_dashboard_usage(business_unit_id,start_time,end_time)
            if dashboard_usage['Status'] == 'Success':
                services = jmespath.search('data[].name', dashboard_usage['data'])
                if len(services) > 0:
                    return {"data": services,'Status':'Success'}
                else:
                    return {"data": 'No services found','Status':'Failure'}
            else:
                return dashboard_usage
        except Exception as e:
            self.forticasb_logging.exception(e)
            
    def get_alert_list(self,business_unit_id, service, start_time, end_time, skip=0, limit=50):
        '''Get cloud service account alert details.'''
        try:
            self.headers.update({'buId':str(business_unit_id)})
            self.headers.update({'service':service})

            payload = {
                'service':service,
                'startTime':start_time,
                'endTime':end_time,
                'skip':skip,
                'limit':limit
            }
            response = self.make_rest_call('/alert/list',
                                      method='POST',
                                      data=payload,
                                      debug=True
                                      )
            if response['Status'] == 'Success':
                return response
            else:
                raise Exception(response)

        except Exception as e:
            self.forticasb_logging.exception(e)
            raise Exception(e)
