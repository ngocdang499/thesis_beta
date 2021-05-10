from neo4j import GraphDatabase

from configparser import ConfigParser

CONFIG_FILE = 'database.ini'
SECTION     = 'neo4j'


def config():
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(CONFIG_FILE)

    # get section, default to postgresql
    dbConfig = {}
    if parser.has_section(SECTION):
        params = parser.items(SECTION)
        for param in params:
            dbConfig[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(SECTION, CONFIG_FILE))
    return dbConfig


class Neo4jConnection:

    def __init__(self, uri, user, pwd):
        self.__uri = uri
        self.__user = user
        self.__pwd = pwd
        self.__driver = None
        try:
            self.__driver = GraphDatabase.driver(self.__uri, auth=(self.__user, self.__pwd))
        except Exception as e:
            print("Failed to create the driver:", e)

    def close(self):
        if self.__driver is not None:
            self.__driver.close()

    def query(self, query, db=None):
        assert self.__driver is not None, "Driver not initialized!"
        session = None
        response = None
        try:
            session = self.__driver.session(database=db) if db is not None else self.__driver.session()
            response = list(session.run(query))
        except Exception as e:
            print("Query failed:", e)
        finally:
            if session is not None:
                session.close()
        return response










