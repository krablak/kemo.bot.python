import time
import datetime
import kemo
import kemo.encryption_default

kemo_api = kemo.Kemo(
    secret_key="timebot",
    ws_url="wss://kemoundertow-krablak.rhcloud.com:8443/messaging/",
    encryption_module=kemo.encryption_default
)


# Sample handler message printin message to output
def print_received_message(message):
    print "Received message %s" % message


# Register handler function
kemo_api.add_on_message_handler(print_received_message)

# Send messages in infinite loops
while True:
    kemo_api.send_msg(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    time.sleep(5)
