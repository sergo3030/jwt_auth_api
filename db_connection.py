import pymysql
from pymysql.cursors import DictCursor
import sql_queries as queries
import utils
from config import config
from routers.custom_http_exceptions import exceptions
from schemas import UserAllData

logger = utils.initiate_logger(__name__)
db_config = config["db"]


class RDBConnection:
    def __init__(self):
        self.connection = pymysql.connect(host=db_config["server"],
                                          user=db_config["user"],
                                          password=db_config["password"],
                                          database=db_config["database"],
                                          autocommit=True,
                                          cursorclass=DictCursor)

    def get_user_details(self, alias: str) -> UserAllData:
        with self.connection.cursor() as cursor:
            result = cursor.execute(queries.GET_USER_DETAILS.format(TABLE=db_config["table"],
                                                                    ALIAS=alias))
            if result == 0:
                logger.error(msg=f"User {alias} doesn't exist in DB")
                raise exceptions["login_exception"]
            fetched_result = cursor.fetchall()
            existing_user_data = fetched_result[0]
            user_data = UserAllData(**dict(existing_user_data))
            return user_data
