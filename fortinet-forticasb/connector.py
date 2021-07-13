""" connector.py"""

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import check_health, operations

logger = get_logger('fortinet-FortiCASB')


class FortiCASB(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            params.update({"operation":operation})            
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as Err:
            raise ConnectorError(Err)

    def check_health(self, config):
        return check_health(config)
