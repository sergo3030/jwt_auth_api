CREATE_TABLE = """
    CREATE TABLE {TABLE} (id MEDIUMINT NOT NULL AUTO_INCREMENT,
                          username VARCHAR(60) NOT NULL,
                          full_name VARCHAR(60) NOT NULL,
                          email VARCHAR(60) NOT NULL,
                          hashed_password VARCHAR(60) NOT NULL,
                          permissions VARCHAR(20) NOT NULL,
                          creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                          PRIMARY KEY (id),
                          UNIQUE (username),
                          UNIQUE (email));
"""

GET_USER_DETAILS = """
    SELECT * FROM {TABLE}
    WHERE username = '{ALIAS}' OR email = '{ALIAS}';
"""
