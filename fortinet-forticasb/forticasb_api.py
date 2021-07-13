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
                self.forticasb_logging.exception('Authentication Failed {}'.format(response.content))
                raise

        except Exception:
            self.forticasb_logging.exception("Authentication Failed")
            raise


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
                return {'data':response.json(),'Status':'Success'}
            else:
                self.forticasb_logging.exception({"data": response.content,'Status':'Failed with Status Code: '+str(response.status_code)})
                return {"data": response.content,'Status':'Failed with Status Code: '+str(response.status_code)}

        except Exception:
            self.forticwp_logging.exception("Request Failed")

    def get_resource_map(self):
        '''Get the user and account basic information from FortiCASB'''

        return self.make_rest_call('/resourceURLMap')

    def get_business_unit_ids(self):
        '''List all available Business Units IDs'''

        bu_list = []
        resource_map = self.get_resource_map()
        if resource_map['Status'] == 'Success':
            for resource in resource_map['data']:
                if len(resource['buMapSet']) > 0:
                    bu_list += jmespath.search('buMapSet[].buId', resource)
                    return list(dict.fromkeys(bu_list))
        else:
            return resource_map
    

    def _get_dashboard(self,business_unit_id,start_time,end_time,dashboard):
        ''' Get Dashboard'''

        payload = {"startTime":start_time,"endTime":end_time}
        self.headers.update({'buId':str(business_unit_id)})
        self.headers.update({'timeZone':strftime("%z", gmtime())})
        return self.make_rest_call('/dashboard/'+dashboard,
                                  method='POST',
                                  data=payload
                                  )

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
        except Exception:
            self.forticwp_logging.exception("Request Failed")
            
    def get_alert_list(self,business_unit_id, service, start_time, end_time, skip=0, limit=50):
        '''Get cloud service account alert details.'''

        self.headers.update({'buId':str(business_unit_id)})
        self.headers.update({'service':service})
        
        payload = {
            'service':service,
            'startTime':start_time,
            'endTime':end_time,
            'skip':skip,
            'limit':limit
        }
        return self.make_rest_call('/alert/list',
                                  method='POST',
                                  data=payload,
                                  debug=True
                                  )
