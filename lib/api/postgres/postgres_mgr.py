#!/usr/bin/env python
import psycopg2

class PostgresDatabaseError(Exception): pass

class PostgresManager():

    def __init__(self, log, secret_mgr):
        self.LOG = log
        self.LOG.info('Initializing Heroku PG DB Mgr')
        self.HOST = secret_mgr.get_secret('MOPS_FLASK_DB_HOST') 
        self.DBPW = secret_mgr.get_secret('MOPS_FLASK_DB_PW')
        self.USR = secret_mgr.get_secret('MOPS_FLASK_DB_USER')
        self.DBNAME = secret_mgr.get_secret('MOPS_FLASK_DB_NAME')
        self.PORT = '5432'

    # generic query
    def query(self, q):
        conn = None
        res = None
        try:
            conn = psycopg2.connect(host=self.HOST, port=self.PORT, database=self.DBNAME, user=self.USR, password=self.DBPW)
            cur = conn.cursor()
            cur.execute(q)
            res = cur.fetchall()
            self.LOG.info(f'PostgresManager_debug - query: {q}')
            # self.LOG.info(f'PostgresManager_debug - res: {res}')
            cur.close()
        except Exception as e:
            self.LOG.warning(f"PostgresManager_debug - PG Database connection failed due to {e}") 
            raise PostgresDatabaseError(f'PG Database Error: {e}. query: {q}')
            return False
        finally:
            if conn is not None:
                conn.close()
        return res

    ###### customer_gifts

    # get a customer_gifts with a given unique_id
    def get_customer_gift_by_email_contact_account(self, email, contact_id, account_id):
        rows = None
        conn = None
        try:
            sql = """
                select *
                from customer_gifts
                where
                    test_mode != true
                    and (
                        account_sfdc_id = %s
                        or email = %s
                        or contact_sfdc_id = %s
                    )
            """
            conn = psycopg2.connect(host=self.HOST, port=self.PORT, database=self.DBNAME, user=self.USR, password=self.DBPW)
            cur = conn.cursor()
            cur.execute(sql, (account_id, email, contact_id))
            rows = cur.fetchall()
            conn.commit()
            self.LOG.info(f'PostgresManager_debug - rows 1: {rows}')
            cur.close()
        except Exception as e:
            self.LOG.warning(f"PostgresManager_debug - PG Database connection failed due to {e}") 
            # raise PostgresDatabaseError(f'Error inserting customer_gifts into Postgres. email: {kwargs.get("email")} | Error: {e}')
            return False
        finally:
            if conn is not None:
                conn.close()

        self.LOG.info(f'PostgresManager_debug - rows 2: {rows}')
        return rows


    # get a customer_gifts with a given a gift code
    def get_customer_gift_by_gift_code(self, gift_code):
        rows = None
        conn = None
        try:
            sql = """
                select *
                from customer_gifts
                where
                    customer_gift_code = %s
                    and test_mode != true
            """
            conn = psycopg2.connect(host=self.HOST, port=self.PORT, database=self.DBNAME, user=self.USR, password=self.DBPW)
            cur = conn.cursor()
            cur.execute(sql, (gift_code))
            rows = cur.fetchall()
            conn.commit()
            self.LOG.info(f'PostgresManager_debug - rows 1: {rows}')
            cur.close()
        except Exception as e:
            self.LOG.warning(f"PostgresManager_debug - PG Database connection failed due to {e}") 
            # raise PostgresDatabaseError(f'Error inserting customer_gifts into Postgres. email: {kwargs.get("email")} | Error: {e}')
            return False
        finally:
            if conn is not None:
                conn.close()

        self.LOG.info(f'PostgresManager_debug - rows 2: {rows}')
        return rows



    # insert a new customer_gifts row
    def insert_customer_gift(self, **kwargs):
        new_id = None
        conn = None
        try:
            sql = """
                INSERT INTO customer_gifts
                (email,first_name,last_name,address1,address2,city,state,zip,country,sku,order_number,tracking_code,tracking_url,customer_gift_code,account_sfdc_id,contact_sfdc_id,account_name,opp_close_order,opp_amount,account_lifetime_bookings,test_mode,opportunity_sfdc_id,confirm_url,status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING *
            """
            conn = psycopg2.connect(host=self.HOST, port=self.PORT, database=self.DBNAME, user=self.USR, password=self.DBPW)
            cur = conn.cursor()
            cur.execute(sql, (kwargs.get('email'),kwargs.get('first_name'),kwargs.get('last_name'),kwargs.get('address1'),kwargs.get('address2'),kwargs.get('city'),kwargs.get('state'),kwargs.get('zip'),kwargs.get('country'),kwargs.get('sku'),kwargs.get('order_number'),kwargs.get('tracking_code'),kwargs.get('tracking_url'),kwargs.get('customer_gift_code'),kwargs.get('account_sfdc_id'),kwargs.get('contact_sfdc_id'),kwargs.get('account_name'),kwargs.get('opp_close_order'),kwargs.get('opp_amount'),kwargs.get('account_lifetime_bookings'),kwargs.get('test_mode'),kwargs.get('opportunity_sfdc_id'),kwargs.get('confirm_url'),kwargs.get('status')))
            new_id = cur.fetchone()[0]
            conn.commit()
            self.LOG.info(f'PostgresManager_debug - new_id 1: {new_id}')
            cur.close()
        except Exception as e:
            self.LOG.warning(f"PostgresManager_debug - PG Database connection failed due to {e}") 
            # raise PostgresDatabaseError(f'Error inserting customer_gifts into Postgres. email: {kwargs.get("email")} | Error: {e}')
            return False
        finally:
            if conn is not None:
                conn.close()

        self.LOG.info(f'PostgresManager_debug - new_id 2: {new_id}')
        return new_id


    # update a customer_gifts status
    def update_customer_gift_status(self, pg_id, status):
        conn = None
        try:
            sql = """
                UPDATE customer_gifts
                SET status = %s
                WHERE id = %s
            """
            conn = psycopg2.connect(host=self.HOST, port=self.PORT, database=self.DBNAME, user=self.USR, password=self.DBPW)
            cur = conn.cursor()
            cur.execute(sql,(status,pg_id))
            conn.commit()
            self.LOG.info(f'PostgresManager_debug - customer_gifts status updated. pg_id: {pg_id}')
            cur.close()
        except Exception as e:
            self.LOG.warning(f"PostgresManager_debug - PG Database connection failed due to {e}") 
            # raise PostgresDatabaseError(f'Error updating sequence_rotator_run into Postgres DB. unique_id: {unique_id} | Error: {e}')
            return False
        finally:
            if conn is not None:
                conn.close()

        return True

    # get customer_gifts without an order number
    def get_non_canceled_customer_gift_without_order_number(self):
        rows = None
        conn = None
        try:
            sql = """
                select *
                from customer_gifts
                where 
                    created_date >= '2022-08-01'
                    and test_mode != 'true'
                    and email not like '%@verkada%'
                    and order_number is null
                    and status not like '%CANCELED%'
                order by
                    created_date asc
                limit
                    10
            """
            conn = psycopg2.connect(host=self.HOST, port=self.PORT, database=self.DBNAME, user=self.USR, password=self.DBPW)
            cur = conn.cursor()
            cur.execute(sql)
            rows = cur.fetchall()
            conn.commit()
            self.LOG.info(f'PostgresManager_debug - (get_non_canceled_customer_gift_without_order_number) rows 1: {rows}')
            cur.close()
        except Exception as e:
            self.LOG.warning(f"PostgresManager_debug - (get_non_canceled_customer_gift_without_order_number) PG Database connection failed due to {e}") 
            # raise PostgresDatabaseError(f'Error inserting customer_gifts into Postgres. email: {kwargs.get("email")} | Error: {e}')
            return False
        finally:
            if conn is not None:
                conn.close()

        self.LOG.info(f'PostgresManager_debug - (get_non_canceled_customer_gift_without_order_number) rows 2: {rows}')
        return rows

