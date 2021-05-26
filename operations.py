""" operations.py """

import logging
import arrow
from requests.models import Response
from integrations.crudhub import maybe_json_or_raise
from connectors.core.connector import get_logger, ConnectorError
from .forticasb_api import FortiCasbCS


logger = get_logger('fortinet-FortiCASB')
#logger.setLevel(logging.DEBUG)

def FortiCASB_init(config):
    try:
        if config.get('server_url')[:8] == 'https://':
            server_url = config.get('server_url')
        else:
            server_url = 'https://{}'.format(config.get('server_url'))             

        FortiCASB = FortiCasbCS(
        base_url=server_url, 
        forticasb_credentials = config.get('api_key'),
        verify_ssl = config.get('verify_ssl'),
        logger = logger
        )
        return FortiCASB
    except Exception as e:
        logger.exception("Failed to connect: {}".format(e))
        raise ConnectorError("Failed to connect: {}".format(e))

def check_health(config):
    try:
      forticasb = FortiCASB_init(config)
      response = forticasb.get_resource_map()
      logger.info("Invoking check_health: {}".format(response['Status']))
      if response['Status'] == 'Success':
          return True
      else:
          return False

    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))

def _get_call(config, params):
    ''' _get_call '''
    try:
        forticasb = FortiCASB_init(config)
        _operation = params.get("operation")
        if _operation == 'get_resource_map':
            return forticasb.get_resource_map()
        elif _operation == 'get_business_unit_ids':
            return forticasb.get_business_unit_ids()
        
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))

def _post_call(config, params):
    '''POST'''
    try:
        forticasb = FortiCASB_init(config)
        _operation = params.get("operation")
        business_unit_id = params.get("business_unit_id")
        start_time = params.get("start_time")
        end_time = params.get("end_time")
        service = params.get("service")
        skip = params.get("skip")
        limit = params.get("limit")
        if start_time:
            start_time = round(arrow.get(start_time).timestamp()) * 1000
        if end_time:
            end_time = round(arrow.get(end_time).timestamp()) * 1000
        if not isinstance(start_time, int) or not isinstance(end_time, int):
            return {'data':'Invalid Start Time or End Time','Status':'Failure'}
        if start_time > end_time:
            return {'data':'Start Time cannot be more recent than End Time','Status':'Failure'}
        if _operation == 'get_bu_services':
            return forticasb.get_bu_services(business_unit_id, start_time, end_time)
        if _operation == 'get_dashboard_risk':
            return forticasb.get_dashboard_risk(business_unit_id, start_time, end_time)          
        if _operation == 'get_dashboard_usage':
            return forticasb.get_dashboard_usage(business_unit_id, start_time, end_time)
        elif _operation == 'get_business_unit_ids':
            return forticasb.get_bu_services(business_unit_id, start_time, end_time)
        elif _operation == 'get_alert_list':
            return forticasb.get_alert_list(business_unit_id,service, start_time, end_time, skip, limit)
        
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))

operations = {
    "get_resource_map": _get_call,
    "get_business_unit_ids": _get_call,
    "get_dashboard_risk": _post_call,
    "get_dashboard_usage": _post_call,
    "get_bu_services": _post_call,
    "get_alert_list": _post_call,
}