import sqlite3


class Credentials:
    def __init__(self):
        self.conn = sqlite3.connect("credentials.db")
        self.cursor = self.conn.cursor()

    def create_master_pass_table(self):
        create_table_sql = """
                    CREATE TABLE IF NOT EXISTS master_password (
                        password TEXT NOT NULL PRIMARY KEY
                    );"""
        self.cursor.execute(create_table_sql)
        self.conn.commit()

    def create_credentials_table(self):
        create_table_sql = """
                    CREATE TABLE IF NOT EXISTS credentials (
                        website TEXT NOT NULL PRIMARY KEY,
                        login TEXT NOT NULL,
                        password TEXT NOT NULL UNIQUE
                    );"""
        self.cursor.execute(create_table_sql)
        self.conn.commit()

    def set_master_password(self, password):
        sql_command = "INSERT INTO master_password (password) " \
                      "VALUES('{}');".format(password)
        self.cursor.execute(sql_command)
        self.conn.commit()

    def get_master_password(self):
        sql_command = "SELECT password FROM master_password;"
        result = self.cursor.execute(sql_command)
        return result.fetchone()[0]

    def set_credentials(self, website, login, password):
        sql_command = "INSERT INTO credentials (website, login, password) " \
                      "VALUES('{}', '{}', '{}');".format(website, login, password)
        self.cursor.execute(sql_command)
        self.conn.commit()

    def update_credentials(self, website, login, password):
        sql_command = "UPDATE credentials " \
                      "SET password = '{2}' WHERE website = '{0}' AND login = '{1}';".format(website, login, password)
        self.cursor.execute(sql_command)
        self.conn.commit()

    def get_credentials(self, website, login):
        sql_command = "SELECT password FROM credentials WHERE website = '{}' AND login = '{}';".format(website, login)
        result = self.cursor.execute(sql_command)
        return result.fetchone()

    def delete_credentials(self, website, login):
        sql_command = "DELETE FROM credentials WHERE website = '{}' AND login = '{}';".format(website, login)
        self.cursor.execute(sql_command)
        self.conn.commit()
