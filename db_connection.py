import pymysql

import sql_queries as queries
import utils
from routers.custom_http_exceptions import exceptions
from schemas import UserAllData
from config import config

logger = utils.initiate_logger(__name__)
db_config = config["db"]


class RDBConnection:
    def __init__(self):
        self.connection = pymysql.connect(
            host=db_config["server"],
            user=db_config["user"],
            password=db_config["password"],
            database=db_config["database"],
            autocommit=True)

    def get_user_details(self, alias: str) -> UserAllData:
        with self.connection.cursor() as cursor:
            result = cursor.execute(queries.GET_USER_DETAILS.format(TABLE=db_config["table"],
                                                                    ALIAS=alias))
            if result == 0:
                logger.error(msg=f"User {alias} doesn't exist in DB")
                raise exceptions["login_exception"]
            results_list = self._get_users_models(cursor)
            for result in results_list:
                existing_user = UserAllData(**result)
                return existing_user

    def _get_users_models(self, cursor) -> list:
        query_results = cursor.fetchall()
        column_names = self._get_column_names(columns_description=cursor.description)
        results_list = self._match_keys_and_values(column_names, query_results)
        return results_list

    @staticmethod
    def _get_column_names(columns_description: tuple) -> tuple:
        columns_names = []
        for column in columns_description:
            column_name = column[0]
            columns_names.append(column_name)
        column_names = tuple(columns_names)
        return column_names

    @staticmethod
    def _match_keys_and_values(column_names: tuple, results: tuple) -> list:
        users_details = []
        for result in results:
            user_details = dict(zip(column_names, result))
            users_details.append(user_details)
        return users_details
