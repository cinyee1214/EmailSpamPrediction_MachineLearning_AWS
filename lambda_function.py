import json
import boto3
import email
import base64
import os
import io
import csv
from hashlib import md5
import string
import sys
import numpy as np
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

if sys.version_info < (3,):
    maketrans = string.maketrans
else:
    maketrans = str.maketrans
    
def vectorize_sequences(sequences, vocabulary_length):
    results = np.zeros((len(sequences), vocabulary_length))
    for i, sequence in enumerate(sequences):
       results[i, sequence] = 1. 
    return results

def one_hot_encode(messages, vocabulary_length):
    data = []
    print("inside one hot")
    print(messages)
    for msg in messages:
        print(msg)
        temp = one_hot(msg, vocabulary_length)
        print("temp")
        print(temp)
        data.append(temp)
    return data

def text_to_word_sequence(text,
                          filters='!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n',
                          lower=True, split=" "):
    """Converts a text to a sequence of words (or tokens).
    # Arguments
        text: Input text (string).
        filters: list (or concatenation) of characters to filter out, such as
            punctuation. Default: `!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n`,
            includes basic punctuation, tabs, and newlines.
        lower: boolean. Whether to convert the input to lowercase.
        split: str. Separator for word splitting.
    # Returns
        A list of words (or tokens).
    """
    if lower:
        text = text.lower()

    if sys.version_info < (3,):
        if isinstance(text, unicode):
            translate_map = dict((ord(c), unicode(split)) for c in filters)
            text = text.translate(translate_map)
        elif len(split) == 1:
            translate_map = maketrans(filters, split * len(filters))
            text = text.translate(translate_map)
        else:
            for c in filters:
                text = text.replace(c, split)
    else:
        translate_dict = dict((c, split) for c in filters)
        translate_map = maketrans(translate_dict)
        text = text.translate(translate_map)

    seq = text.split(split)
    return [i for i in seq if i]

def one_hot(text, n,
            filters='!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n',
            lower=True,
            split=' '):
    """One-hot encodes a text into a list of word indexes of size n.
    This is a wrapper to the `hashing_trick` function using `hash` as the
    hashing function; unicity of word to index mapping non-guaranteed.
    # Arguments
        text: Input text (string).
        n: int. Size of vocabulary.
        filters: list (or concatenation) of characters to filter out, such as
            punctuation. Default: `!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n`,
            includes basic punctuation, tabs, and newlines.
        lower: boolean. Whether to set the text to lowercase.
        split: str. Separator for word splitting.
    # Returns
        List of integers in [1, n]. Each integer encodes a word
        (unicity non-guaranteed).
    """
    return hashing_trick(text, n,
                         hash_function='md5',
                         filters=filters,
                         lower=lower,
                         split=split)


def hashing_trick(text, n,
                  hash_function=None,
                  filters='!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n',
                  lower=True,
                  split=' '):
    """Converts a text to a sequence of indexes in a fixed-size hashing space.
    # Arguments
        text: Input text (string).
        n: Dimension of the hashing space.
        hash_function: defaults to python `hash` function, can be 'md5' or
            any function that takes in input a string and returns a int.
            Note that 'hash' is not a stable hashing function, so
            it is not consistent across different runs, while 'md5'
            is a stable hashing function.
        filters: list (or concatenation) of characters to filter out, such as
            punctuation. Default: `!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n`,
            includes basic punctuation, tabs, and newlines.
        lower: boolean. Whether to set the text to lowercase.
        split: str. Separator for word splitting.
    # Returns
        A list of integer word indices (unicity non-guaranteed).
    `0` is a reserved index that won't be assigned to any word.
    Two or more words may be assigned to the same index, due to possible
    collisions by the hashing function.
    The [probability](
        https://en.wikipedia.org/wiki/Birthday_problem#Probability_table)
    of a collision is in relation to the dimension of the hashing space and
    the number of distinct objects.
    """
    if hash_function is None:
        hash_function = hash
    elif hash_function == 'md5':
        hash_function = lambda w: int(md5(w.encode()).hexdigest(), 16)

    seq = text_to_word_sequence(text,
                                filters=filters,
                                lower=lower,
                                split=split)
    return [int(hash_function(w) % (n - 1) + 1) for w in seq]


runtime= boto3.client('runtime.sagemaker')

def lambda_handler(event, context):
    #event = {'Records': [{'eventVersion': '2.1', 'eventSource': 'aws:s3', 'awsRegion': 'us-east-1', 'eventTime': '2020-05-01T18:44:09.488Z', 'eventName': 'ObjectCreated:Put', 'userIdentity': {'principalId': 'AWS:AIDAIE26RTG3F45XIHQFI'}, 'requestParameters': {'sourceIPAddress': '10.160.39.34'}, 'responseElements': {'x-amz-request-id': '9A1F3C5D04F1699E', 'x-amz-id-2': '/UUOnhHiF12OdlQynOqUEHcZmtv8D6YwvZBReQYSU3EJNCqxIYJIwX7bLiHKCHnIA1mdJ4lSattwPPwCNKNMLGhVWWoOC0/6'}, 's3': {'s3SchemaVersion': '1.0', 'configurationId': 'invoke-lambda', 'bucket': {'name': 'email-store-sna', 'ownerIdentity': {'principalId': 'A3C8EJ139WMU6O'}, 'arn': 'arn:aws:s3:::email-store-sna'}, 'object': {'key': '9lje3laqvbo2icf3k2af24i1so3kk52irmhj23o1', 'size': 4023, 'eTag': 'eb3626adf918a7d37cdc2c49c357d80b', 'sequencer': '005EAC6DFC21C94AE2'}}}]}
    s3 = boto3.client("s3")
    
    print("My Event is : ", event)

    file_obj = event["Records"][0]
    filename = str(file_obj["s3"]['object']['key'])
    print("filename: ", filename)
    fileObj = s3.get_object(Bucket = "s1emailbucketlab3", Key=filename)
    print("file has been gotten: ", fileObj)

    b = email.message_from_bytes(fileObj['Body'].read())
    # print(b)

    from_address = b['From']
    start = from_address.find('<')
    end = from_address.find('>')
    from_address = from_address[start+1:end]
    print("from_address: ",from_address)
    
    received_time = b['Date']
    end = received_time.find('-')
    received_time = received_time[:end]
    print("received_time: ", received_time)
    
    subject = b['Subject']
    print("subject: ", subject)
    
    if b.is_multipart():
        for payload in b.get_payload():
            print("multi")
            print(payload.get_payload())
            payload_message = payload.get_payload()
            break
    else:
        print("else")
        payload_message = b.get_payload()
        print(b.get_payload())

    print(type(payload_message))
    print(payload_message)
    
    payload_message = payload_message.rstrip()
    payload_message = [payload_message]
    #payload_message = ["FreeMsg: Txt: CALL to No: 86888 & claim your reward of 3 hours talk time to use from your phone now! ubscribe6GBP/ mnth inc 3hrs 16 stop?txtStop"]
    #payload_message1 = {"features": [payload_message]}
    #payload_message = ["hi which language is this?"]
    #payload_message1 = {"instances" : payload_message}
    #dataElement = [0.0 ,0.0 ,0.0, 0.0, 0.0]
    #temp = {"features": {"values": dataElement}}
    #temp = b'[0.0, 1.0, 0.0, 0.0]'
    vocabulary_length = 9013
    one_hot_test_messages = one_hot_encode(payload_message, vocabulary_length)
    print(one_hot_test_messages)
    print(len(one_hot_test_messages))
    encoded_test_messages = vectorize_sequences(one_hot_test_messages, vocabulary_length)
    #encoded_test_messages = "FreeMsg: Txt: CALL to No: 86888 & claim your reward of 3 hours talk time to use from your phone now! ubscribe6GBP/ mnth inc 3hrs 16 stop?txtStop"
    print(type(encoded_test_messages))
    print(len(encoded_test_messages))
    print(len(encoded_test_messages[0]))
    print(encoded_test_messages)
    msg = json.dumps(encoded_test_messages.tolist())
    
    response = runtime.invoke_endpoint(EndpointName='sms-spam-classifier-mxnet-2021-04-20-19-53-47-082',
                                  ContentType='application/json',
                                  Accept='application/json',
                                  Body=msg)
                                   
    print(response)
    result = json.loads(response['Body'].read().decode())
    print(result)
    pred = result['predicted_label'][0][0]
    predicted_probability = result['predicted_probability'][0][0]

    predicted_label = 'SPAM' if pred == 1 else 'HAM'
    print('predicted_label ', predicted_label)
    
    return_msg = "We received your email sent at "+str(received_time) + " with the subject "+ str(subject) +". Here is a 240 character sample of the email body: "+ str(payload_message[:240]) +" The email was categorized as "+ str(predicted_label) +" with a "+ str(predicted_probability) +"% confidence."
    print(return_msg)
    

    EMAIL_HOST = 'email-smtp.us-east-1.amazonaws.com'
    EMAIL_HOST_USER = "AKIA2BLXEQCBWH7TEGG7" # Replace with your SMTP username
    EMAIL_HOST_PASSWORD = "BG0Lie3RXAPGdoaRq/Dcu6GmrqlIWcqPnhu1Em/pN1eK" # Replace with your SMTP password
    EMAIL_PORT = 587
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Result for EMAIL"
    msg['From'] = "lab3@nyucloud.me"
    msg['To'] = from_address
    
    msg.attach(MIMEText(return_msg))
    
    s = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
    s.starttls()
    s.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
    s.sendmail("lab3@nyucloud.me", from_address, msg.as_string())
    s.quit()
        
        
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
    
