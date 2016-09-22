import collections
import socket
from email import utils
from ago import human
from django.core import signing
from django.conf import settings
from django.utils import timezone
from datetime import timedelta, datetime
from django.core.urlresolvers import reverse
from django.utils.timezone import utc
from notification.models import SlackRoom, HipChatRoom
import whois
from pygeoip import GeoIP
from deepdiff import DeepDiff
import re

DOMAIN = settings.DOMAIN_NAME

import logging

LOG = logging.getLogger(__name__)

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def fqdn_to_ip(fqdn):
    """Util function to get IP for a given fqdn
    """
    ip_addr = socket.gethostbyname(fqdn)
    return ip_addr


def decode(token, expiring=True):
    """
    Use Django signing to decode the token.
    :param token: the token object (signed)
    :return: decoded dictionary if success, else None
    """
    try:
        if expiring:
            val = signing.loads(token, max_age=settings.TOKEN_LIFETIME)
        else:
            val = signing.loads(token)
    except Exception as e:
        LOG.info("The token seems to be invalid (%s)" % str(e))
        val = None
    return val


def encode(d):
    """
    Encode the object (dict) using django signing
    :param d: the Dictionary object to sign (encode)
    :return: the encoded object
    """
    val = None
    if isinstance(d, dict):
        try:
            val = signing.dumps(d)
        except Exception as e:
            LOG.error("Error occurred during encoding (%s)" % str(e))
    return val


def _get_snooze_timestamp(td):
    now = timezone.now()
    later = now + td
    return later.strftime(TIME_FORMAT)


def generate_sslcheck_email_links(email, sslcheck_id):
    url = "https://%s%s" % (DOMAIN, reverse('ssl_no_auth'))
    ret = dict(unsubscribe=None, snooze={})

    # Snooze links
    for x in settings.DAYS_TO_SSL_SNOOZE:
        d = dict(action="snooze",
                 email=email,
                 snooze_days=x,
                 snooze_until=_get_snooze_timestamp(x),
                 sslcheck_id=sslcheck_id)
        ret['snooze'][x] = "%s?tk=%s" % (url, encode(d))

    # Unsubscribe link
    d = dict(action="unsubscribe",
             email=email,
             sslcheck_id=sslcheck_id)
    ret['unsubscribe'] = "%s?tk=%s" % (url, encode(d))
    return ret


def datetime_json_encoder(obj):
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def ack_notification_email_link(emails=None, notification_id=None, snooze_durations=[]):
    ack_urls_for_emails = {}

    for email in emails:

        url = "https://%s%s" % (DOMAIN, reverse('notification_no_auth'))
        ack_urls = collections.OrderedDict()

        for x in snooze_durations:
            d = dict(action="ack", email=email,
                     snooze_duration=humanize_snooze_durations(x),
                     ack_untill=_get_snooze_timestamp(x),
                     notification_id=notification_id)

            ack_urls[humanize_snooze_durations(x)] = "%s?tk=%s" % (url, encode(d))

        ack_urls_for_emails[email] = ack_urls

    return ack_urls_for_emails

def time_from_epoch(epoch):
    return utils.formatdate(epoch)


def humanize_snooze_durations(td):
    return human(td).replace(' ago', '')


def parse_whois_data(domain_name):
    """Util function to parse domain's whois Information
    :param domain_name: name of domain for which we want whois information
    :return: tuple containing
    (parsed whois data, no. of days remaining to expire domain, already expire the domain or not)
    """
    whois_data = whois.whois(domain_name).query(redirect=False)
    parsed_whois_data = whois.Parser(domain_name, whois_data[1]).parse()

    try:
        # ExpirationDate format is not consistent
        # some times it return Y-m-dTH:M:S and some times Y-m-d
        parsed_expire_date = parsed_whois_data["ExpirationDate"][0].split('T')[0]
        expiry_date = datetime.strptime(parsed_expire_date, "%Y-%m-%d").replace(tzinfo=utc)
        cur_date = timezone.now()

        expire_days = int((expiry_date - cur_date).days)
        is_expire = True if expire_days <= 0 else False
    except Exception as e:
        expire_days = None
        is_expire = False
        LOG.error("Error occurred during Parsing ExpirationDate for domain %s: (%s)" % (domain_name, str(e)))

    return parsed_whois_data, expire_days, is_expire


def compare_dict(first_dict, second_dict):
    """Util function to compare two dictionaries
    :param first_dict:
    :param second_dict:
    :return: dictionary object with changed Data
    """
    changed_data = DeepDiff(first_dict, second_dict)

    added_items_list = changed_data.changes['list_added'] if 'list_added' in changed_data.changes else None
    removed_items_list = changed_data.changes['list_removed'] if 'list_removed' in changed_data.changes else None

    added_items = {}
    if added_items_list:
        for added_item in added_items_list:
            # DeepDiff returns every thing in string
            # so need to convert it in dictionary
            key, values = added_item.split(":")
            find_key_name = re.search("\[\'(.*?)\'\]", key)
            if find_key_name:
                key_name = find_key_name.group(1)
                added_items[str(key_name)] = eval(values)

    removed_items = {}
    if removed_items_list:
        for removed_item in removed_items_list:
            key, values = removed_item.split(":")
            find_key_name = re.search("\[\'(.*?)\'\]", key)
            if find_key_name:
                key_name = find_key_name.group(1)
                removed_items[str(key_name)] = eval(values)

    return {
        'added_items': added_items,
        'removed_items': removed_items
    }


def country_from_ip(ip, geo_conn=None):
    """
     Helper method to return the coutry_code from
     a given ip address
     :rtype : dict
     :param ip: The ip (string) e.g. 106.185.47.165
     :param geo_conn: The connection object to use
     :return: Two letter country code e.g. JP
    """
    if not geo_conn:
        geo_conn = geo_connection()
    try:
        return geo_conn.country_code_by_addr(ip)
    except Exception as e:
        LOG.error("Error occurred while converting ip %s "
                  " to country code" % (ip))

def geo_connection():
    geo_conn = GeoIP("%s/%s" % (settings.GEOIP_DB_LOCATION,
                                settings.GEOIP_FILENAME))
    return geo_conn
