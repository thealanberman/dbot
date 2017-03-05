from __future__ import print_function

import json
import logging
import os
from urlparse import parse_qs

import boto3
# from boto3.dynamodb.conditions import Attr, Key
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

    # CREATE character
    if action == "create" and len(command_text) >= 2:
        message = create_character(username, channel, arguments)

    # SET stat
    elif action == "set" and len(command_text) == 4:
        message = set_value(username, channel, arguments)

    # GET stat
    elif action == "get" and len(command_text) >= 2:
        message = get_value(username, channel, arguments)

    # SHOW stat
    elif action == "show" and len(command_text) >= 2:
        message = get_value(username, channel, arguments)
        public = True

    # DEL stat
    elif action == "del" and len(command_text) == 3:
        message = del_value(username, channel, arguments)

    # HELP screen
    else:
        message = help_usage()
        public = True

    return {'public': public, 'message': message}
# END parse_command_text


def help_usage():
    '''Returns help screen'''
    response = "You may either `create` `set` `get` or `del`.\n"
    response += "Example Usage:\n"
    response += "`create Trogdor` (creates a new Trogdor character)\n"
    response += "`create Trogdor johndoe` (creates a new character 'Trogdor' with GM 'johndoe')\n"
    response += "`set trogdor str 18` (sets the value of Trogdor's str to 18)\n"
    response += "`get trogdor` (returns all of Trogdor's stats privately)\n"
    response += "`get trogdor str` (returns just Trogdor's str)\n"
    response += "`show trogdor` (returns Trogdor's stats publicly)\n"
    response += "`del trogdor str` (deletes Trogdor's str entirely)"
    return response
# END help_usage


def create_character(slack_username, channel, charval):
    '''Creates a new character. Returns HTTPStatusCode.'''
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
                    'owner_slackname': slack_username,
                    'displayname': character,
                    'gm': game_master
                }
            },
            ConditionExpression="attribute_not_exists(character_channel)",
            ReturnValues="NONE"
        )
        logger.info("response: {}".format(response))
    except ClientError as e:
        logger.info("Error: {}".format(e.response['Error']['Message']))
        response = {'ResponseMetadata': {'HTTPStatusCode': 403}}
    
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        message = "CHARACTER: %s [CREATED]\n" % character
    elif response['ResponseMetadata']['HTTPStatusCode'] == 403:
        message = "A character by that name already exists."
    else:
        message = "Something borked and the Character could not be created."

    return message
# END create_character



def set_value(slack_username, channel, charval):
    '''Sets a stat of the character record passed'''
    # logger.info("slack_username: {}".format(slack_username))
    # logger.info("channel: {}".format(channel))
    character, key, value = charval[0], charval[1], charval[2]
    character_channel = character.lower() + channel.lower()

    try:
        response = dbot.update_item(
            Key={
                'character_channel': character_channel
            },
            UpdateExpression="set stats.%s = :v" % key,
            ConditionExpression="stats.owner_slackname = :slackuser OR stats.gm = :slackuser",
            ExpressionAttributeValues={
                ':v': value,
                ':slackuser': slack_username
            },
            ReturnValues="UPDATED_NEW"
        )
        logger.info("response: {}".format(response))
    except ClientError as e:
        logger.info("Error: {}".format(e.response['Error']['Message']))
        response = {'ResponseMetadata': {'HTTPStatusCode': 403}}

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        message = "Value set!\n"
        message += "CHARACTER: %s\n" % character
        message += "%s: %s\n" % (key.upper(), value)
    elif response['ResponseMetadata']['HTTPStatusCode'] == 403:
        message = "You do not have permission."
    else:
        message = "Something borked and the value could not be set."

    return message
# END set_value


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
                'character_channel': character_channel
            }
        )
        logger.info("response: {}".format(response))
    except ClientError as e:
        logger.info("Error: {}".format(e.response['Error']['Message']))
        response = {'ResponseMetadata': {'HTTPStatusCode': 403}}

    if "Item" not in response:
        return "No such character."
    if response['Item']['stats']['owner_slackname'] != slack_username and response['Item']['stats']['gm'] != slack_username:
        return "You are not the owner or the GM for that character."

    logger.info("response: {}".format(response))

    if k == "":
        message = "*%s*\n" % response['Item']['stats']['displayname']
        del response['Item']['stats']['displayname']
        message += "OWNER: %s\n" % response['Item']['stats']['owner_slackname']
        del response['Item']['stats']['owner_slackname']
        message += "GM: %s\n" % response['Item']['stats']['gm']
        del response['Item']['stats']['gm']
        for key, value in sorted(response['Item']['stats'].iteritems()):
            # logger.info("{}: {}".format(key, value))
            message += "%s: %s\n" % (key.upper(), value)
    else:
        message = "*%s*\n" % response['Item']['stats']['displayname']
        message += k.upper() + ": " + response['Item']['stats'][k]

    return message
# END get_value


def del_value(slack_username, channel, charval):
    '''Deletes a stat from a character'''
    logger.info("slack_username: {}".format(slack_username))
    character, key = charval[0], charval[1]
    character_channel = character.lower() + channel.lower()

    if key == "gm":
        return "Can't delete that. You can `set` it to someone else (including yourself)."
    elif key == "displayname":
        return "Can't delete that. You can `set` it to something else, but you will still need to reference your character by %s." % character
    elif key == "owner_slackname":
        return "Can't delete that."

    try:
        response = dbot.update_item(
            Key={
                'character_channel': character_channel
            },
            UpdateExpression="REMOVE stats.%s" % key,
            ConditionExpression="stats.owner_slackname = :slackuser OR stats.gm = :slackuser",
            ExpressionAttributeValues={
                ':slackuser': slack_username
            },
            ReturnValues="UPDATED_NEW"
        )
        logger.info("response: {}".format(response))
    except ClientError as e:
        logger.info("Error: {}".format(e.response['Error']['Message']))
        return "No such character or you don't have permission to modify that character."

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        message = "CHARACTER: %s\n" % character
        message += "%s: (Deleted)\n" % key.upper()
    else:
        message = "Something borked and the value could not be deleted."

    return message



def lambda_handler(event, context):
    '''Main function triggered by the Lambda'''
    params = parse_qs(event['body'].encode('ASCII'))
    # params = parse_qs(event['body'])
    token = params['token'][0]
    if token != slack_token:
        logger.error("Request token (%s) does not match expected", token)
        return respond(Exception('Invalid request token'))

    user = params['user_name'][0]
    # command = params['command'][0]
    channel = params['channel_name'][0]
    try:
        command_text = params['text'][0].split()
    except KeyError:
        command_text = ['help']

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
