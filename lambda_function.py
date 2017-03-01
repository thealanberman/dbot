from __future__ import print_function

from urlparse import parse_qs
import json
import logging
import os
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

slack_token = os.environ['slack_token']

dbot = boto3.resource('dynamodb', region_name='us-east-1').Table('dbot')

def respond(err, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err.message if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json'
        },
    }


def parse_command_text(username, channel, command_text):
    '''Calls appropriate action for text passed. Returns response message to Slack.'''
    action = command_text[0]
    public = False
    arguments = command_text[1:]
    logger.info("action: {}".format(action))

    # CREATE character
    if action == "create" and len(command_text) >= 2:
        response = create_character(username, channel, arguments)
# TODO what does this return when the character already exists
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            message = "CHARACTER: %s [CREATED]\n" % command_text[1]
        else:
            message = "Something borked and the Character could not be created."


    # SET stat
    elif action == "set" and len(command_text) == 4:
        response = set_value(username, channel, arguments)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            message = "Value set!\n"
            message += "CHARACTER: %s\n" % command_text[1]
            message += "%s: %s\n" % (command_text[2].upper(), command_text[3])
        else:
            message = "Something borked and the value could not be set."

    # GET stat
    elif action == "get" and len(command_text) >= 2:
        message = get_value(username, channel, arguments)

    elif action == "show" and len(command_text) >= 2:
        message = get_value(username, channel, arguments)
        public = True

    # DEL stat
    elif action == "del" and len(command_text) == 3:
        response = del_value(username, channel, arguments)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            message = "CHARACTER: %s\n" % command_text[1]
            message += "%s: (Deleted)\n" % (command_text[2].upper())
        elif response['ResponseMetadata']['HTTPStatusCode'] == "displayname":
            message = "Sorry, you can't delete displayname. You can `set` it to something else, but you will still need to reference your character by it's original name."
        elif response['ResponseMetadata']['HTTPStatusCode'] == "gm":
            message = "gm has been reset to %s. Now only %s can modify %s.\n" % (username, username, command_text[1])
        else:
            message = "Something borked and the value could not be deleted."

    # HELP screen
    else:
        message = help_usage()

    return {'public': public, 'message': message}


def help_usage():
    '''Returns help screen'''
    response = "You may either `create` `set` `get` or `del`.\n"
    response += "Example Usage:\n"
    response += "`create Trogdor` (creates a new Trogdor character)\n"
    response += "`create Trogdor johndoe` (creates a new Trogdor character with johndoe as the GM)\n"
    response += "`set trogdor str 18` (sets the value of Trogdor's str to 18)\n"
    response += "`get trogdor` (returns all of Trogdor's stats privately)\n"
    response += "`get trogdor str` (returns just Trogdor's str)\n"
    response += "`show trogdor` (returns Trogdor's stats publicly)\n"
    response += "`del trogdor str` (deletes Trogdor's str entirely)"
    return response


def create_character(slack_username, channel, charval):
    '''Creates a new character'''
    logger.info("slack_username: {}".format(slack_username))
    logger.info("channel: {}".format(channel))
    character = charval[0]
    character_channel = character.lower() + channel.lower()

    # gm is same as character unless specified otherwise
    try:
        game_master = charval[1]
    except IndexError:
        game_master = slack_username

    try:
        response = dbot.put_item(
            Item={
                'character_channel': character_channel,
                'stats': {
                    'owner': slack_username,
                    'displayname': character,
                    'gm': game_master
                }
            },
            ConditionExpression="attribute_not_exists(character_channel)",
            ReturnValues="NONE"
        )
    except ClientError as e:
        logger.info("Error: {}".format(e.response['Error']['Message']))

    logger.info("response: {}".format(response))
    return response


def set_value(slack_username, channel, charval):
    '''Sets a stat of the character record passed'''
    logger.info("slack_username: {}".format(slack_username))
    logger.info("channel: {}".format(channel))
    character, key, value = charval[0], charval[1], charval[2]
    character_channel = character.lower() + channel.lower()

    try:
        response = dbot.update_item(
            Key={
                'username': slack_username,
                'character_channel': character_channel
            },
            UpdateExpression="set stats.%s = :v" % key,
            ExpressionAttributeValues={
                ':v': value
            },
            ReturnValues="UPDATED_NEW"
        )
    except ClientError as e:
        logger.info("Error: {}".format(e.response['Error']['Message']))

    logger.info("response: {}".format(response))
    return response


def get_value(slack_username, channel, charval):
    '''Returns the value(s) of the character record passed'''
    character = charval[0]
    character_channel = character.lower() + channel.lower()

    try:
        k = charval[1]
    except IndexError:
        k = ""

    try:
        response = dbot.get_item(
            Key={
                'username': slack_username,
                'character_channel': character_channel
            }
        )
    except ClientError as e:
        print(e.response['Error']['Message'])

    if "Item" not in response:
        return "No such character."

    logger.info("response: {}".format(response))

    if k == "":
        message = "*%s*\n" % response['Item']['stats']['displayname']
        del response['Item']['stats']['displayname']
        message += "GM: %s\n" % response['Item']['stats']['gm']
        del response['Item']['stats']['gm']
        for key, value in sorted(response['Item']['stats'].iteritems()):
            # logger.info("{}: {}".format(key, value))
            message += "%s: %s\n" % (key.upper(), value)
    else:
        message = "*%s*\n" % response['Item']['stats']['displayname']
        message += k.upper() + ": " + response['Item']['stats'][k]

    return message


def del_value(slack_username, channel, charval):
    '''Deletes a stat from a character'''
    logger.info("slack_username: {}".format(slack_username))
    character, key = charval[0], charval[1]
    character_channel = character.lower() + channel.lower()

    if key == "gm":
        return {'ResponseMetadata': {'HTTPStatusCode': 'gm'}}
    elif key == "displayname":
        return {'ResponseMetadata': {'HTTPStatusCode': 'displayname'}}

    try:
        response = dbot.update_item(
            Key={
                'username': slack_username,
                'character_channel': character_channel
            },
            UpdateExpression="REMOVE stats.%s" % key,
            ReturnValues="UPDATED_NEW"
        )
    except ClientError as e:
        print(e.response['Error']['Message'])

    logger.info("response: {}".format(response))
    return response


def lambda_handler(event, context):
    '''Main function triggered by the Lambda'''
    params = parse_qs(event['body'].encode('ASCII'))
    # params = parse_qs(event['body'])
    token = params['token'][0]
    if token != slack_token:
        logger.error("Request token (%s) does not match expected", token)
        return respond(Exception('Invalid request token'))

    user = params['user_name'][0]
    command = params['command'][0]
    channel = params['channel_name'][0]
    command_text = params['text'][0].split()

    # message = help_usage()
    logger.info("text: {}".format(command_text))
    logger.info("user: {}".format(user))
    action = parse_command_text(user, channel, command_text)
    if action['public']:
        response_type = "in_channel"
    else:
        response_type = "ephemeral"

    return respond(None, {'text': action['message'], 'response_type':
                          response_type, 'user_name': 'DBot'})
