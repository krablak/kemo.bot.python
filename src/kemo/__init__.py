import logging
import threading
from xml.sax import handler

import websocket

__author__ = 'jesus'

logging.basicConfig(level=logging.DEBUG)


class Kemo(object):
    def __init__(self, secret_key, ws_url, encryption_module):
        # Key used for message encryption and addressing
        self.secret_key = secret_key
        # Module providing functions for encryption/decryption and salting
        self.encryption_module = encryption_module
        # List of functions executed on message receive
        self.on_message_handlers = []
        # Connection open flag
        self.is_open = False
        url = "%s%s/" % (ws_url, encryption_module.key_to_address(self.secret_key))
        logging.debug("connecting to '%s'" % url)
        # Create Websocket client instance
        self.ws = websocket.WebSocketApp(url,
                                         on_message=self.on_message,
                                         on_error=self.on_error,
                                         on_close=self.on_close)
        # Start background communication thread
        self.ws_thread = threading.Thread(target=self.initialize_connection)
        self.ws_thread.start()

    def initialize_connection(self):
        self.ws.on_open = self.on_open
        # websocket.enableTrace(True)
        self.ws.run_forever()

    def add_on_message_handler(self, handler):
        """
        Registers handler function executed on received message.
        Handler function should accept single argument with type string for received message.
        :param handler: registered function.
        """
        if handler:
            self.on_message_handlers.append(handler)

    def on_open(self, ws):
        logging.debug("Websocket client connection was open")
        self.is_open = True

    def on_message(self, ws, enc_message):
        try:
            message = self.encryption_module.decrypt(
                self.encryption_module.salt_encryption_key(self.secret_key),
                enc_message
            )
            for cur_handler in self.on_message_handlers:
                try:
                    cur_handler(message)
                except:
                    logging.exception("Unexpected error when handing message message '%s' using handler: '%s'", message,
                                      handler)
            logging.debug("Received message: %s", message)
        except:
            logging.exception("Unexpected error when decrypting message.")

    def on_error(self, ws, error):
        logging.error("Websocket client error: %s", error)

    def on_close(self):
        logging.debug("Closing websocket client connection.")
        self.ws.close()

    def send_msg(self, msg):
        if self.is_open and msg and len(msg.strip()) > 0:
            logging.debug("Sending message: %s", msg)
            try:
                enc_message = self.encryption_module.encrypt(
                    self.encryption_module.salt_encryption_key(self.secret_key), msg)
                self.ws.send(enc_message)
            except:
                logging.exception("Unexpected error when encrypting message.")
        else:
            logging.debug("Websocket connection is not open. Cannot send message.")
