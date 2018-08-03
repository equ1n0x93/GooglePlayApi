import requests
import logging
import sys
import urllib2
import urllib
import json
import zlib

from cookielib import CookieJar
import gpsoauth

from google.protobuf import descriptor
from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from google.protobuf.pyext._message import RepeatedCompositeContainer
from google.protobuf import text_format
from google.protobuf.message import Message, DecodeError

import googleplay_pb2 as googleplay_pb2

logging.basicConfig(stream=sys.stdout,
                    format='%(asctime)s | %(levelname)-8.8s | %(filename)s | %(process)d | %(message).10000s',
                    datefmt='%Y/%m/%d %H:%M:%S',
                    level=logging.DEBUG)
logger = logging


class TooManyRequests(Exception):

    def __init__(self):
        Exception.__init__(self)
        self.status_code = 429
        self.message = 'Too many requests'


class LoginError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class GoogleTokenExpired(Exception):
    pass


class MarketTokenExpired(Exception):
    pass


class RequestError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class GooglePlayAPI(object):
    """Google Play Unofficial API Class

    Usual APIs methods are login(), search(), details(), bulkDetails(),
    download(), browse(), reviews() and list().

    toStr() can be used to pretty print the result (protobuf object) of the
    previous methods.

    toDict() converts the result into a dict, for easier introspection."""

    SERVICE = "androidmarket"
    URL_LOGIN = "https://android.clients.google.com/auth"  # "https://www.google.com/accounts/ClientLogin"
    ACCOUNT_TYPE_GOOGLE = "GOOGLE"
    ACCOUNT_TYPE_HOSTED = "HOSTED"
    ACCOUNT_TYPE_HOSTED_OR_GOOGLE = "HOSTED_OR_GOOGLE"

    EMBEDDED_SETUP_URL = 'https://accounts.google.com/embedded/setup/android?source=com.android.settings&xoauth_display_name=Android%20Phone&canSk=1&lang=en&langCountry=en_us&hl=en-US&cc=us'
    GMS_CORE_VERSION = '11302438'
    SDK_VERSION = 23

    def __init__(self, androidId, email, password, google_token=None, lang=None, debug=False, login=True,
                 authSubToken=None, proxy=None):  # you must use a device-associated androidId value

        self.preFetch = {}
        self.android_authentication_session = requests.Session()
        self.google_signin_session = requests.Session()
        self._google_signin_cookiejar = CookieJar()
        self._google_signin_session = urllib2.build_opener(urllib2.HTTPCookieProcessor(self._google_signin_cookiejar))
        self._android_auth_cookiejar = CookieJar()
        self._android_auth_session = urllib2.build_opener(urllib2.HTTPCookieProcessor(self._android_auth_cookiejar))
        self.email = email
        self.psw = password
        self.androidId = androidId
        self.lang = lang
        self.debug = debug
        self.authSubToken = authSubToken
        self.google_token = google_token
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        if self.google_token:
            logger.info('google token exists: {}'.format(self.google_token))
        if self.authSubToken:
            logger.info('auth sub token exists: {}'.format(self.authSubToken))
        if login:
            self.loginV2()
            # self.login()

    def _get_embedded_token(self, txt):
        import json
        dic = json.loads(txt[txt.find('{'):txt.find('}') + 1])
        freq = txt[txt.find('en_us&quot;,&quot;') + len('en_us&quot;,&quot;'):]
        freq_token = freq[:freq.find('&')]
        return dic['OewCAd'].split('\n')[1][2:-2], freq_token

    def _get_embedded_info(self):
        resp = self._google_signin_session.open(self.EMBEDDED_SETUP_URL)
        content = _get_resp_content(resp)
        return self._get_embedded_token(content)

    def toDict(self, protoObj):
        """Converts the (protobuf) result from an API call into a dict, for
        easier introspection."""
        iterable = False
        if isinstance(protoObj, (RepeatedCompositeFieldContainer, RepeatedCompositeContainer)):
            iterable = True
        else:
            protoObj = [protoObj]
        retlist = []

        for po in protoObj:
            msg = dict()
            for fielddesc, value in po.ListFields():
                # print value, type(value), getattr(value, "__iter__", False)
                if fielddesc.type == descriptor.FieldDescriptor.TYPE_GROUP or \
                    isinstance(value, (RepeatedCompositeFieldContainer, RepeatedCompositeContainer)) or \
                    isinstance(value, Message):
                    msg[fielddesc.name] = self.toDict(value)
                else:
                    msg[fielddesc.name] = value
            retlist.append(msg)
        if not iterable:
            if len(retlist) > 0:
                return retlist[0]
            else:
                return None
        return retlist

    def toStr(self, protoObj):
        """Used for pretty printing a result from the API."""
        return text_format.MessageToString(protoObj)

    def _try_register_preFetch(self, protoObj):
        fields = [i.name for (i,_) in protoObj.ListFields()]
        if ("preFetch" in fields):
            for p in protoObj.preFetch:
                self.preFetch[p.url] = p.response

    def setAuthSubToken(self, authSubToken):
        logging.info("Auth token set: '%s'" % authSubToken)
        self.authSubToken = authSubToken

        # put your auth token in config.py to avoid multiple login requests
        if self.debug:
            print "authSubToken: " + authSubToken

    def loginV2(self, accountType=ACCOUNT_TYPE_HOSTED_OR_GOOGLE):
        encryptedPassword = gpsoauth.google.signature(self.email, self.psw, gpsoauth.android_key_7_3_29)
        params = {"Email": self.email, "EncryptedPasswd": encryptedPassword,
                  "service": self.SERVICE,
                  "accountType": accountType, "has_permission": "1",
                  "source": "android", "android_id": self.androidId,
                  "app": "com.android.vending", "sdk_version": "17",
                  "add_account": "1"}
        resp = requests.post(self.URL_LOGIN, params)
        logging.info("Attempting login to google services")

        if resp.status_code == 200:
            logging.info("Login request status code - 200")
            data = resp.content
            data = data.split()
            params = {}
            for d in data:
                k, v = d.decode().split("=", 1)
                params[k.strip()] = v.strip()
            if "Auth" in params:
                self.setAuthSubToken(params["Auth"])
            else:
                raise LoginError("Auth token not found.")
        else:
            if resp.status_code in [401, 403]:
                raise LoginError("Login request failed, status code: %d" % resp.status_code)
            else:
                data = resp.content
                raise LoginError("Login failed: error %d <%s>" % (resp.status_code, data.rstrip(),))

    def login(self):
        if not self.google_token:
            self._get_google_signign()
            self.google_token = self._get_google_token()
        self.authSubToken = self.authSubToken or self._get_android_auth_token()

    def old_login(self, email=None, password=None, authSubToken=None):
        """Login to your Google Account. You must provide either:
        - an email and password
        - a valid Google authSubToken"""
        if authSubToken is not None:
            self.setAuthSubToken(authSubToken)
        else:
            if (email is None or password is None):
                # raise Exception("You should provide at least authSubToken or (email and password)")
                email = self.email
                password = self.psw
            params = {"Email": email,
                                "Passwd": password,
                                "service": self.SERVICE,
                                "accountType": self.ACCOUNT_TYPE_HOSTED_OR_GOOGLE,
                                "has_permission": "1",
                                "source": "android",
                                "androidId": self.androidId,
                                "app": "com.android.vending",
                                # "client_sig": self.client_sig,
                                "device_country": "fr",
                                "operatorCountry": "fr",
                                "lang": "fr",
                                "sdk_version": "16"}
            headers = {
                "Accept-Encoding": "",
            }
            response = requests.post(self.URL_LOGIN, data=params, headers=headers, verify=False)
            data = response.text.split()
            params = {}
            for d in data:
                if not "=" in d: continue
                k, v = d[:d.find('=')], d[d.find('=')+1:]
                params[k.strip().lower()] = v.strip()
            if "auth" in params:
                self.setAuthSubToken(params["auth"])
            elif "error" in params:
                raise LoginError("server says: " + params["error"])
            else:
                raise LoginError("Auth token not found.")

    def execute_request_raw(self, path, datapost=None, post_content_type=None):
        post_content_type = post_content_type or "application/x-www-form-urlencoded; charset=UTF-8"

        if datapost is None and path in self.preFetch:
            data = self.preFetch[path]
        else:
            headers = {
                "Accept-Language": self.lang,
                "Authorization": "GoogleLogin auth=%s" % self.authSubToken,
                "X-DFE-Enabled-Experiments": "cl:billing.select_add_instrument_by_default",
                "X-DFE-Unsupported-Experiments": "nocache:billing.use_charging_poller,market_emails,buyer_currency,prod_baseline,checkin.set_asset_paid_app_field,shekel_test,content_ratings,buyer_currency_in_app,nocache:encrypted_apk,recent_changes",
                "X-DFE-Device-Id": self.androidId,
                "X-DFE-Client-Id": "am-android-google",
                #"X-DFE-Logging-Id": self.loggingId2, # Deprecated?,
                "User-Agent": "Android-Finsky/7.4.12.L-all%20%5B0%5D%20%5BPR%5D%20144479971(api=3,versionCode=80741200,sdk=23,hardware=qcom,product=WW_Phone,platformVersionRelease=6.0.1,isWideScreen=0)",
                "X-DFE-SmallestScreenWidthDp": "320",
                "X-DFE-Filter-Level": "3",
                "Accept-Encoding": "",
                "Host": "android.clients.google.com"
            }

            if datapost is not None:
                headers["Content-Type"] = post_content_type

            url = "https://android.clients.google.com/fdfe/%s" % path
            if datapost is not None:
                response = requests.post(url,
                                         data=datapost,
                                         headers=headers,
                                         verify=False,
                                         proxies=self.proxy,
                                         timeout=30)

            else:
                response = requests.get(url,
                                        headers=headers,
                                        verify=False,
                                        proxies=self.proxy,
                                        timeout=30)

            logger.info('headers are %s' % dict(response.headers))
            if response.status_code == 429:
                raise TooManyRequests

            data = response.content
            return data

    def executeRequestApi2(self, path, datapost=None, post_content_type=None, raw_response=None):

        data = raw_response or self.execute_request_raw(path=path,
                                                        datapost=datapost,
                                                        post_content_type=post_content_type)

        message = googleplay_pb2.ResponseWrapper.FromString(data)
        self._try_register_preFetch(message)
        return message

    #####################################
    # Google Play API Methods
    #####################################

    def search(self, query, nb_results=None, offset=None):
        """Search for apps."""
        path = "search?c=3&q=%s" % requests.utils.quote(query) # TODO handle categories
        if (nb_results is not None):
            path += "&n=%d" % int(nb_results)
        if (offset is not None):
            path += "&o=%d" % int(offset)

        message = self.executeRequestApi2(path)
        return message.payload.searchResponse

    def getFeatureGraphic(self, package_id, webp=True):
        """
        Gets URL of certain package feature graphic
        :param package_id: String of package id
        :param webp: Boolean if to return the URL of the original feature image in webp format or unknown png/jpg
        :return: String of the searched URL
        """
        feature_graphic_image_type = 2
        path = "details?doc=%s" % requests.utils.quote(package_id)

        message = self.executeRequestApi2(path)
        app_dict = self.toDict(message.payload.detailsResponse)
        if len(app_dict) == 0:
            return None
        app_images = app_dict["docV2"]["image"]
        url = None

        for image in app_images:
            if image["imageType"] == feature_graphic_image_type:
                url = image["imageUrl"] + "="
                if webp == True:
                    url += "rw-"
                url += "w1024"

        if url:
            resp = requests.get(url, proxies=self.proxy, timeout=30)
            return resp.content

    def details(self, packageName, get_raw=False):
        """Get app details from a package name.
        packageName is the app unique ID (usually starting with 'com.')."""
        path = "details?doc=%s" % requests.utils.quote(packageName)
        raw_response = self.execute_request_raw(path)
        message = self.executeRequestApi2(path, raw_response=raw_response)
        if get_raw:
            return message.payload.detailsResponse, raw_response
        return message.payload.detailsResponse

    def bulkDetails(self, packageNames):
        """Get several apps details from a list of package names.

        This is much more efficient than calling N times details() since it
        requires only one request.

        packageNames is a list of app ID (usually starting with 'com.')."""
        path = "bulkDetails"
        req = googleplay_pb2.BulkDetailsRequest()
        req.docid.extend(packageNames)
        data = req.SerializeToString()
        message = self.executeRequestApi2(path, data, "application/x-protobuf")
        return message.payload.bulkDetailsResponse

    def browse(self, cat=None, ctr=None):
        """Browse categories.
        cat (category ID) and ctr (subcategory ID) are used as filters."""
        path = "browse?c=3"
        if (cat != None):
            path += "&cat=%s" % requests.utils.quote(cat)
        if (ctr != None):
            path += "&ctr=%s" % requests.utils.quote(ctr)
        message = self.executeRequestApi2(path)
        return message.payload.browseResponse

    def list(self, cat, ctr=None, nb_results=None, offset=None):
        """List apps.

        If ctr (subcategory ID) is None, returns a list of valid subcategories.

        If ctr is provided, list apps within this subcategory."""
        path = "list?c=3&cat=%s" % requests.utils.quote(cat)
        if (ctr != None):
            path += "&ctr=%s" % requests.utils.quote(ctr)
        if (nb_results != None):
            path += "&n=%s" % requests.utils.quote(nb_results)
        if (offset != None):
            path += "&o=%s" % requests.utils.quote(offset)
        message = self.executeRequestApi2(path)
        return message.payload.listResponse

    def reviews(self, packageName, filterByDevice=False, sort=2, nb_results=None, offset=None):
        """Browse reviews.
        packageName is the app unique ID.
        If filterByDevice is True, return only reviews for your device."""
        path = "rev?doc=%s&sort=%d" % (requests.utils.quote(packageName), sort)
        if (nb_results is not None):
            path += "&n=%d" % int(nb_results)
        if (offset is not None):
            path += "&o=%d" % int(offset)
        if(filterByDevice):
            path += "&dfil=1"
        message = self.executeRequestApi2(path)
        return message.payload.reviewResponse

    def snippets(self, path):
        message = self.executeRequestApi2(path)
        return message.payload.snippetResponse

    def download(self, packageName, versionCode, offerType=1):
        """Download an app and return its raw data (APK file).

        packageName is the app unique ID (usually starting with 'com.').

        versionCode can be grabbed by using the details() method on the given
        app."""
        path = "purchase"
        data = "ot=%d&doc=%s&vc=%d" % (offerType, packageName, versionCode)
        message = self.executeRequestApi2(path, data)

        url = message.payload.buyResponse.purchaseStatusResponse.appDeliveryData.downloadUrl
        cookie = message.payload.buyResponse.purchaseStatusResponse.appDeliveryData.downloadAuthCookie[0]

        cookies = {
            str(cookie.name): str(cookie.value) # python-requests #459 fixes this
        }

        headers = {
                   "User-Agent" : "AndroidDownloadManager/4.1.1 (Linux; U; Android 4.1.1; Nexus S Build/JRO03E)",
                   "Accept-Encoding": "",
                  }

        response = requests.get(url, headers=headers, cookies=cookies, verify=False, proxy=self.proxy, timeout=30)
        return response.content

    def _init_post_data(self, azt):
        data = {}
        data['azt'] = azt
        data[
            'bgRequest'] = '["identifier","!CwilCClCiO_zvljVfvFEE5m8wgYWoIACAAADTFIAAACMCgALa38WLLaEjVHPIEGZARWMqcZwkLGalmEGEQjRiUjihT8fJl4XhdA_KyjXyK5bEp2HbC5g1nuemvhD42E8Fg0Xi9jAXxeXG9vjjBGO7LykbK9VG3S3X6DN6_IGZ5q69AdFEXh4cBeAc9quxS0emYxyzm9ijVkOxOpznDrqALj1WYhZAnLbzbLKOr_Fp7ytgSUEeAfn_fDtFouX3dNZddtJCuQTH7GpODTWb5co5xsFr39Q9_nYPLYowy780hi8DOGrqThtmVklATLo2lTiP-MnVashNmZ0ycAMkw9zLaSnmVrAx-CF0IHl1ISrl1-UbO-kuT1SvDftkm5fL-hFZ1HWhF128rN1242oyl3-xdS4dURG82GTrZT1K_9RyxcKCZ0kHrOh"]'
        data[
            'continue'] = 'https://accounts.google.com/o/android/auth?lang=en&cc&langCountry=en_&xoauth_display_name=Android+Device&source=android&tmpl=new_account&return_user_id=true'
        data[
            'deviceinfo'] = '["{device_id}",{sdk_version},{gms_core},[],true,"IL",0,null,[],"EmbeddedSetupAndroid",null,[0,null,[],null,null,"{device_id}"],1]'.format(
            device_id=self.androidId, sdk_version=self.SDK_VERSION, gms_core=self.GMS_CORE_VERSION)
        data[
            'dgresponse'] = '["CgbcQ1WPVn_YAQHaB4kEAOuhCBL4IcUChls2x9HNjmLu_YOau138gygEqrmA_1NvXV05gz0CL5YOzEY43PpmHi92YbbBeb5lcwvZhDn0m5x5-Oyj5G16QZPAF02a7dlkuZvHySULpTzCgjqGZF7H1KA8U1Tm_X4AJ8sas0Qt9QVp9y9SG_cBBpWz9uFLkCMzPj2xRvhG5zpgMdeVbec6hsi-WqkKsDGNjcboqkkSb8QQQlsO5tmHqpVJ0AACKz7GBH1TUZ6Pj5FokOwNS8vyJwTfQZtm6I9wxUyMyzEyWdu_DeeJihxDWYeHOqzHjl3snDUIIkMGQ_53nV_lqbt1364PQM_sMomSOZ8XfTzrGGDBYUn8t2_8eCI_iU6RjuWCFaYBlqafQYZj3N0KZW9eL9TnP8TnayKMPf7PKhd_mdLaqH5wde7kBDpSyo96roQspnVHy-cyBhOyAwjbSzVPCXi3PdSmDJiqKZKVEL9xk47u3x2Lq7D9kYvRIOtt2VW0L86IfTiLViCO5UDCuLHe3aXAa4iKHP5UtrFwK-_sCCX3gB0QW4SlRVfaY51G-LHmkcOFF84bPZzE5MbIWClmQQzMDovO_Mp3wlgV9w3wq5PGJomU01qx7Zp3OgFdWNJbW2ibtNi3f3TgdSLH0HcY-71WyTC3iOXhZeGgCW-BtlRPbOP6qiuHxidWFA4EbQGHjBYEvERkuTI4YRoRCJOQ6dX6_____wEQi_7k1AfoAd6gj6f7_____wHoAdKl1YD7_____wE4azhLEu4sJQ1gxf6h6051LDAxEFK6iRd4dn5B41k03FMjPMU9mhkRe5ef8fhgEPaGO4Ce9q39sbuHtmPVy6lJ0sHQ1Xf7Hfecm3RElJmJ0svkqyj1HWh5Jgo2FxZD4nb32b5lItTZBhN493jod4j-ymRFkvDa3hZwNGsTOHt5vXFQk0fO8AsqOzVekf2sV6Sc_3KNPGs8BUCawWiMbItwnkYTyIJ5y9bv2Og0gJyn0OyCvR1xCcvSJiDX1xDi_5kdDHdncQ7OhqK2rGrX5vflEmYI6bkTIeFlPKrmrNH9-i6v3X0SApQRzwpVe0rzBn2ucAgHyWRdAq5Q9bV-Hj6Z7y_ocQ3nm3QQbMaXbZ2WBb7uQrMLksczMg1Ilfd60W1JdAHpG2KQmBbCQoLj8iHI5D22WGwg8WOrdJnuly_yLZyhgLLZos6sMEWUy9auXl8kbgG6UjI_Owbi-D46fOWa-zWQCWA_SQMmm0_L_WkzHyia_EYZ3NVGXBfgwO06kLqvmODKytE-G0o27cIlXxlXJW9-icMlco8ntaJnRH5sY-WeFxkVoOoZjCWCtJMzyiwOzW3lJz6d_bw1WcItEBmQqCKZr0vGajRRRK5KEbJrZtx-KykdT41ePwIqDT4AxZAznvZriwen66Wor48_M0SD3AbpaxPKtcLnhvRcoa6_y7ecFJEm1tAyoiIRHGz-3AP-85mobbIQVSp18fhem-stn6raFXnCYfHnyWjacsOK73gvoK1YtP6jIJvEDywhQ4SvFf-ObPaicXZSKA4D7kh3G3p3v0_JrtVzod1isyHacWQDXuBci3bbZwrZZ8tls1-1Z3pefhoSt6pdIQe5nGshYtFR8JTdwPQulfbpgsbClxoSBC6ZBueeB_N9XtlMcMY_4r_1kcnAUyXMeZ_l2Umh6bKs_MTYou6-XbL6uJfJY4wWftNE8ImYbz3Zun9DUTuUz4SSj_29xdTZY6asmBnhBE9aOnyL_Mha5rJWb6FUBSFOVgHpQvrf1O8rzHXDEna4QjW-2iNk1eGLc3mx_nWb9czqA4DgKm3R2wv7HkSpR8fFyefjX1Bi7M9rdfFDMH1BU6GMb0oExXys8DXeKlj_fxrOQf7OFDUVv0n_vQFLa6vJldSrgkWyb__QCxqd87Vuelv0GjSOWVLdjerWK80a--i0hD5cvfO8JR94PiwE-G1cjmyHKV1J9R_DxxMPk49SQnnS0uWt1A_0g12MOHTy1Sg2CTkjLDPa1tH7bva6UXlsztzxFmXes53gdz84Xa-QEgl4CNbC5EsJeLNWNzgTH4Tik3fTVpGEpqUw59lZv2NBwWKxCvaXoRR7dYt8DtW8PbGyXMG4pk6kxPUearh7-Qe3M8fBCUw61ioMGKeNMIn-y5t4YUl3KFAdWHq6LXDTY8fp82wvQANYCl47I-pMk-wXaJ9iP8nXYBA-58el9XIWlz9dnnU61pG0zQywOKzMAxU19yCc7NefnaEpB7WQzHwwse3Nc1Hir9TyddxHamAhzKjXnPRp4qPjNcAa78iBW6X8hof7TKoSWcFZQb2He7QuCIGZqlI1C1ldc9EGPRVOJEEy7TspcLCsHcUygmSiOb-eydN7P23PRi870lsvX_xtBpk_NKLT1lj1AYLIslLRnmbSEBQzhOCnWVrkEu7yqUWBmwD18Cj7AxzftyiIMLzaMTOwzAHHkMGcsTPGNHMTFu7EzyX0AgHMoyQWMPHFSV1bIGaW0dE8Qq-cv_4i4aDfAOerFReZsIiLDEsaHqJDNkvTSOtmXpFYw2QdKhILnah4jHGC2MRrSsAIyyoUf3vngaGAQWSL_5AC6upp1_zuA6LdMLRbiOMkR9raRu9VKnm5dBSjYHMQ3o7ZkzYvIdEpdFncoIruc0RMdVWMZnMX9883fPoZJ5-mK7fBm-PtKwk7LGzeL3SF-i4zsxYuuMempDQCxSHm9tA259_XfZXjIWKk8UomCph85mdb-rezIKiek-sUqdJIm0hXb_-7oQRRZ_0LVeeI7ltl7dCyqFS5ohbnRsm4v4DrpdITaTeltRhGU6s6hia7zXKSwae48tQr2RGkf1rAG0xador38PeLiaotfZDmQXukvDEfb2a-zU_j57emlBheoisps9uiM2AYjpejNZUB01aJB4lTFn51gbIvHsPcVIp--NB0GTPApkK4ndA91LUz-P8UvR0CFulehrxIkmu_gTC-0Se0LA-AGs5WMIMv0Ie8W00rcZx-oGz5m-pYThA9BJytk7cr3EYLKnIBphDsCqMzizVI1Ih3thz7GecL7VIPkgi_ekQU7QzGp4_LrEdqkehGJyDTZtzK69-KITa1uadCx7BwCZ8ec1LYE5aJZIiPj2zDfMctnQlvkp0INhTQOTuKMMlFt18WLdHwGXXggfaFw6W8C6lq9BsPm-9UW3wP4Wpaz8XtSIf8xLScKtoxh3g30yXOJ12oIfUkTSQMDiTNDJZrNtnru5v4LQlDxntpg0Z2L-Tt_pSQkKZKnD9YcZATpGAqCT4wQfrZkUY01Vol_jbLijiWTJE6RD5Dd2ecXCms_dh3u1Z6jZYvZC4cXh-CgbM5ykHktsS0dcem8fuV-HxNtb9MDpcAG5fekrE2FrXbUQS8FrpWTLAdx0vgEkopPoivo-Hm3-mEkGnCkUIqh3o07LZpkARvvmUpWRYuESjvUacAQcddwlV08Zsh6wehizQXWpNXBm-yJKfQvzNBx4YOd2z3fmloYzyOt1P5_JAjfbLSsi1Ec1uUc1x9Qqgzkfeaf5GLJt7eCcXXN1NFwMQ_hE7Mlbp9TQfpdqkzyfS0x0tq_6RLgYy9NqO3QK5nIIQKp4bazcjJwLlZfxjZjXUdb5ZyvGmCN6Q60vBYsGNLrl1OOTxCbJn_a7UyeEPWqVd9xQ4h6d71HoAZKPGeogi5YZHqjMXAlGsoVp0heBgCyBvXXfMlZnxdlXBYkpGh_UvnMWrklwLNy03qgAvZLOGyY58nm2hO40Do6VeGzr2cJTy8tR1GfXPlmPxiPbnzDvF8GRbYm-OLDGUV8AOLfhZrEaD2eBsRzawhCDTDrv2rREcnDnzWfa2S7UzqtJZWOOXLMjT8COZNIX88lxZAXu0yY2jlpvLiOTd6ACQ1CyCzACNvZZNo1KtPHhdm6AVZIYUX2z8kLKz-D802kALgh0M5c-T4QsfoLs5-nNqWbGzOpCSfGtBYLVfkxKXdgCcn_Bq8vDzF3wBxXS5mfMTcb0EJTeI9cjFDbhFRF2pRlAihVkhvkqZZcCDJbg0sg-OF_bzHZpvP5Cs5WqxyR8ohM0CpgHQhZNyNAOYAPRDRcSqUJBYX2sJAiKFFclalvI-WbFBhQRUjnx9FFIZHf5pZOvXnNWy0Gy0u4hkhcTJGCB3f90rSOYBW42CSPsBqNkpgoGJ49KslN7hMTCe9f9S5lAEaXSuD4LYnq_VDwvpdLecvR2Qxr77gFCI7lPgi9s4zo79Qge2v7bmse3LmKSOZSZ7Jo3lGDTP6ugGmWc-poX3XHZI0GhXrkGUFA0Xj4WiyERDgrHniZfAOqcvgrVJTaFpO6Pb4_Ml6NPC39uKWJByiL_Oiu9uCLGrvsa4ZxtwGqhGUM5uvoa8ip-ctaB3vga-mgma_tKDq0IlRaBkvGYzsrfm9Bbid3Qib--s5KTcwvDkDrrYWAuFvwZ5EPBRZhD3k9doigU1EFzjJWnizzgUtXYYzyjHTOSO9j4O0ngb1a_hM5g8oRNjoIKFf1oJJQNxctiIPdMAiZvqEcesb5xrsn4clrNbarLEme9n0ARfAnZkVAF6Q0pXuI1RctFVwE0xK6zn9Jp6fNdikLpgRaTzkKarywQHG8hMZpr8QwbrUPoetsTAbtKcj1oQgDPkW7CIIIadl_E3IkuZl8eC3xAWZJ-EjfYbs3-veMdjH8Eh4mAJVDN7qM3cbpt8pxEuNJ2cpLLW2x0xMnANQ6XxPHwNL8rjGPzipf1NwzUJPb3gmPWKZilrcUIFQPcJAW4KB1mkDiVy6icb-DT8c-ERHpvQHJ0O5e0r4Y9ERtnaKF7OAqjTVaqwALqorhSxMV5UDi74utGUO9oxPQk5BH-CJyedvlquINUbN50CwckRetl2f1ay0HN-hBgBGlIVdI13he8ZSWtNVwhhS4CJKgqFpYfvrmjHkfsbR0gmnpOsd0WgM6jhnWQYIJwx4KXktqMFuVdeC6Sh3Op816zJYaBsxbbViGxabnwKt4OXlxeaazjYe93SLFQPxJFrJAL7UWCawS5RZe5QP0ENorI6KDD0uKFycZAwKdBq6DpHJ4sxBDesDrpg22xzC_BtAmoUjfp8AH-dZ-xgAB0AAIESYmQKPZvywubmS5X1phbyYCPjV6REV84mc8VhPpeUfmy7JmMeVFLzGFXeX4xXUgR32kJqvZbgjMAPBpG6OWNKp2FslObN2G5NxHbfkEMkfexp7YOXmjHJYXSlSit3gJmhByaoY5wI9rz2aJn1Q4iO3AHSckyaXx4JZ9_lwmQGpTkF8OEYBQzktfLEEPJF489-kvTKa66Y3fQ34l-tA5iWtNmZbDdXkRTsefPCl8rsjwSFItpSjya0BwS2L3Ig7m_Q5_tzbnLlaJr6N1L9jzDDKpYw3-uxDQlvjgA6dV83xTG_v0pXWwfp5gMzhGh7b8uff-oGsyQvbj0LzNS-cXpERrVsSULfAEf-ZPFzmBIkprxHeWyZHSYLfcL0sDt41FfadM5iRk_DO4kDFqBSV-cG-YFFNa5g8T1sQAdgrFRcB4smka4YlN5L0vAuOhjeNx__yHr0zVVXc5fogsgbX6qdaxmFaK1xpzoiz-OSSO-2h_VQpNTC3x_hL8p1dcTqK9c3QOvp-KWYYkPSfICpvXWI2WuUNBagE2yM_A2wAQ2fk05EGDs7bba-aqKxjenC27eddVItiXrXA4OiKmTHJimbdJnItZyFQ7LiJSr2xCliCUSQwvYsdv_2R2ek8XzEgQrnYMvOEhvzj48aff5ppWTcPD6cHXrewtw1CsH0RctS4JNfhx0Bjr2iXFlXYV8UnVl8xJWYqpQvmrvwrC9UBK49DsPlPGClFQUphoc7fqwuLJkgJqWcU88hixeXNp4GSWuQYvnyiF9ucGNtv_DkRy9bPrOgePP4SvcoJa6jq20iMfVpBhbKct9fJCOaB8W5Xmqwo3vj509JH_32m4B7uOIost-USb8N5ThRTK-wrmhV6uQauGiOt9YzV57EILIcDFWsGapCKBac7m91i9BfVtNXS7jo81x19GKlUDIZoQD8CBaN3QJqcMwdTx3rnaleUb2f-HiMSkThkuJ9v2_CKhgWI8x2u7fvpeyf-WmRvI1mLFs6HPgJVZg8WDbUn01EY0KQBpDd-ePoQjxXRfKORl4UmBR5dMeLeU0dAT7-h1GDBRhwDtGMmVW-NVYQp2XRePR27kuioyqocY5TcykOysBR-SKAEA8n05n34Xh-WolU_8y0CWmQntbNknAu8BCcxJgpQPDshnWH-uemq2Rs-DJZpyJhjPhcWyPayArqgt10EZkd2h8BW4_vX8SWIenQQVVTcTFOZjnQ-7u_UggfuSraZaTzAXbG8jhVa0eyOs9OK-QO5cThQvu1nFBYvjCkajn3Y7SzN_yGR4pFZz_ThAJe53ZQ-CjL6Uau0uEBM1TlXdV2psH8piinRQ7Q1cJHL_2mVzlIEnqYV-90peO8emALP8vP6o70eKt_UrF87_qCA92mfnKgbOTIRx1wAE0hdjLCxREVa8mk1j8KeMQfbvfHfXX7w_ZF6GN6XlLucJyuYYuNM97JJ21FcD2-TvlB7mvVt-VcDHwEB7FfVc8ns_O-hDy6Uw_WSrRQZrwdFazuUPNrUYhoPZ9XlTY4L6IE2WrOvWg2Z3db9f1XC0ThO0YEKj9Vv-CoKPxmmtLnJ0nSWgLMt9LbrEfluJQHRpAHSG8Kq72fdWFKFtZDUf4YsPRcehL6PpSk7FzHkpncEvjmCJ5OlLkqPk-ueq4oEu1Lnl8OLPBrFUe8bXJJskHrX9dST8rpU20p7pZgPE6AR6U5FxFCvRC3XJWkqzmKGLFJNzqJdxehnwZ3XCn9h5Bjdb-sVVVmJbDgA9WjknRlfsZQY_9eV8zCt2NSb35jCsjN9RDcyisj6ia7eVRJngC4rAM4z6pVC9_DIw0Dcg2sxa4Xa-Pj_L236_t_LfcqP4rDNU_VvvP32FTqFVru6f66p14PMTPO-eCgcdNA57q6Pm8r1KDPw7SYk4Vfgrq9rDgu13dB0sjyBLQ59zsif_N8tJxH6SePFW2b1CnI8v_rEkw6AGZC-zw38Xf0p3LdEJkrK_o8fLvcjjwyDC8kL0ejOx8Tt0713ZZHPDtQQZusrFEElUXBa_pXLPk7dQzoBDr8jFF74_I-v6JqKGewzMfH-QgaWNYWcNhgoJaixhIieMA-BEcIQypK40Qqxmb0RSRGded2fNch9EvcX_MHx7psZycfdPL43lKSMa3YMBhLHoPVbNxNslhRYlfiumK_nTkfOWx3awen_YPgc4LUzd2nQbvKxKSt-_0wiDDvIOTeoofjvhZWUofCTs5_fXj5qoT0V8pZ6H47lmvKDWZpcaL78OjKieXBaeXXuF8_CXoZ57Ck1XO6J9KsML8aHf3In1gYvzdyksiRdI-O-FMpbjdq7t8Wo0PFD599_2SQXdN3avEKeZafsXhTym5ccJlxHgJTucVPqDQIZsZaEHmQWZni-eNOaMt_WSwT4MfeTkQ8Z0gT_UCd2Scx9LmfflI3G14pQbVduFiqEThbKwKTos9EUnahosSqYyiWaJL-aOGB1CzrXNMizEpXUsyvZJPafn78HHGap6xdrfgM-ajyXUjEZh9Hbsi9yj_2JoyGxO21i7yvsON8T1Kmo56euYOIMKg4KJ5wRhBsCJTemXLyf_GQnegtdi000CjeL26TKWUAS_dkLJwmt3PeEyT7VJlusJ4g1YzgWIs-IdMXkBPxk7zLJwsJ-yKDgps372so7SnuJZyZaMBpB5l264iOlAPJmu3CuASy9_ymigSv-gVR5mBlTZFUcYYuWa1PnzkJzeyR47HmEaLPIcgHRlzX33F2SmBrSi7BXCvaTAA3tRI7DqJTOdYQ8TzmNiT0u2kn--O7YP0Ndrkx_NPldXnIIpJwouENjSrM8IQenVRik6kBlPVAI6PxWORch0vXdbICDkYOGf8tdfkXWT5WP1TRQtI49oSwx7MNW5riyN-J5KgZCyOgojxCx5WuCLWpYUbC0ZXDfhgrUpgr8p__gcp7AAjtkw0Yg8lGxFB_wCyxTOvQrP5HZnGaKSKDY9ugMtmAhQ2C-9OcOj5KCGY5Q1AbRT4RRyBtlOMWkCaH--m8fru9bpmYlOefIhtDZzXy8wqWwnSWGrJBmCW6we8hmpMLa6pT-W355Mp5eyKbUlJZr_ntEWrXPuzG6VVF92u71oUkpbfMgJO0YED2iStGwaZF9ceJwHlei3cvAEC6H7pHKlwquuLiSZTfa5XWBnqJiccwlrqG2QMQ50EuhsxEWTxc4rXiDqkg51sFhtCeuu4F1xdsIHn3Z2TBGkoH4bOqxRvMes4tvvJYJZDB6jbCZsubtJXy8Op-so96EuEs8mt2wVuyKbF42te0kABC3g-O71sPiwnUqXIXWV8DQxOunQZ66-TEXAJNk"]'
        data['gmscoreversion'] = '%s' % self.GMS_CORE_VERSION
        return data

    def _lookup_request(self, azt, freq_token):
        data = self._init_post_data(azt)
        data[
            'f.req'] = '["{email}","{freq_token}",[],null,"US",null,null,2,true,true,[null,null,[1,1,0,1,"https://accounts.google.com/EmbeddedSetup?source=com.android.settings&xoauth_display_name=Android+Phone&canSk=1&lang=en&langCountry=en_us&hl=en-US&cc=us",null,[],3],2,[0,null,[]],null,null,null,false],"{email}"]'.format(
            email=self.email, freq_token=freq_token)
        params = [('hl', 'en'), ('_reqid', '44751'), ('rt', 'j')]
        headers = {'accept': '*/*',
                   'accept-encoding': 'gzip, '
                                      'deflate',
                   'accept-language': 'en-US',
                   'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
                   'google-accounts-xsrf': '1',
                   'origin': 'https://accounts.google.com',
                   'referer': 'https://accounts.google.com/embedded/setup/android/identifier?source=com.android.settings&xoauth_display_name=Android%20Phone&canSk=1&lang=en&langCountry=en_us&hl=en-US&cc=us&flowName=EmbeddedSetupAndroid',
                   'user-agent': 'Mozilla/5.0 '
                                 '(Linux; '
                                 'Android '
                                 '6.0.1; '
                                 'SM-G900F '
                                 'Build/MMB29M; '
                                 'wv) '
                                 'AppleWebKit/537.36 '
                                 '(KHTML, '
                                 'like '
                                 'Gecko) '
                                 'Version/4.0 '
                                 'Chrome/59.0.3071.125 '
                                 'Mobile '
                                 'Safari/537.36 '
                                 'MinuteMaid',
                   'x-requested-with': 'com.google.android.gms',
                   'x-same-domain': '1'}
        self._google_signin_session.addheaders = headers.items()
        full_url = 'https://accounts.google.com/_/lookup/accountlookup?' + urllib.urlencode(params)
        resp = self._google_signin_session.open(full_url, data=urllib.urlencode(data))

        # resp = self.google_signin_session.post('https://accounts.google.com/_/lookup/accountlookup', params=params,
        #                 headers=headers, data=urllib.urlencode(data))
        return json.loads(_get_resp_content(resp)[6:])

    def _challenge_request(self, lookup_resp, azt):
        data = self._init_post_data(azt)
        data['f.req'] = '["{lookup_token}",null,1,null,[1,null,null,null,["{password}",null,true]]]'.format(
            lookup_token=lookup_resp[0][0][2],
            password=self.psw)
        headers = {'accept': '*/*',
                   'accept-encoding': 'gzip, '
                                      'deflate',
                   'accept-language': 'en-US',
                   'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
                   'google-accounts-xsrf': '1',
                   'origin': 'https://accounts.google.com',
                   'user-agent': 'Mozilla/5.0 '
                                 '(Linux; '
                                 'Android '
                                 '6.0.1; '
                                 'SM-G900F '
                                 'Build/MMB29M; '
                                 'wv) '
                                 'AppleWebKit/537.36 '
                                 '(KHTML, '
                                 'like '
                                 'Gecko) '
                                 'Version/4.0 '
                                 'Chrome/59.0.3071.125 '
                                 'Mobile '
                                 'Safari/537.36 '
                                 'MinuteMaid',
                   'x-requested-with': 'com.google.android.gms',
                   'x-same-domain': '1'}
        params = [('hl', 'en'), ('TL', lookup_resp[0][1][2]),
                  ('_reqid', '133258'),
                  ('rt', 'j')]

        self._google_signin_session.addheaders = headers.items()
        full_url = 'https://accounts.google.com/_/signin/challenge?' + urllib.urlencode(params)
        resp = self._google_signin_session.open(full_url, data=urllib.urlencode(data))

        if not resp.code == 200:
            logger.error('failed with google login challenge, status code: {}'.format(resp.status_code))
            logger.error(_get_resp_content(resp))
            raise LoginError('failed to pass google signin challenge, suspicious behavior may be detected')

        return json.loads(_get_resp_content(resp)[6:])

    def _challenge_consent(self, lookup_resp, azt):
        data = self._init_post_data(azt)
        data.pop('bgRequest', None)
        data.pop('dgresponse', None)
        params = [('hl', 'en'), ('TL', lookup_resp[0][1][2]), ('_reqid', '233258'), ('rt', 'j')]
        data['f.req'] = '["gf.siesic",1,[]]'
        headers = {'accept': '*/*', 'accept-encoding': 'gzip, deflate', 'accept-language': 'en-US',
                   'content-type': 'application/x-www-form-urlencoded;charset=UTF-8', 'google-accounts-xsrf': '1',
                   'origin': 'https://accounts.google.com',
                   'user-agent': 'Mozilla/5.0 '
                                 '(Linux; '
                                 'Android '
                                 '6.0.1; '
                                 'SM-G900F '
                                 'Build/MMB29M; '
                                 'wv) '
                                 'AppleWebKit/537.36 '
                                 '(KHTML, '
                                 'like '
                                 'Gecko) '
                                 'Version/4.0 '
                                 'Chrome/59.0.3071.125 '
                                 'Mobile '
                                 'Safari/537.36 '
                                 'MinuteMaid',
                   'x-requested-with': 'com.google.android.gms',
                   'x-same-domain': '1'}

        # resp = self.google_signin_session.post('https://accounts.google.com/_/signin/speedbump/embeddedsigninconsent',
        #                                        params=params, headers=headers, data=urllib.urlencode(data))
        self._google_signin_session.addheaders = headers.items()
        full_url = 'https://accounts.google.com/_/signin/speedbump/embeddedsigninconsent?' + urllib.urlencode(params)
        resp = self._google_signin_session.open(full_url, data=urllib.urlencode(data))

        if not resp.code == 200:
            logger.error('failed with google login challenge')
            logger.error(_get_resp_content(resp))
            raise LoginError('failed to pass google signin speedbump, suspicious behavior may be detected')

        return _get_resp_content(resp)

    @staticmethod
    def _find_cookie(cj, cookie_name):
        for cookie in cj:
            if cookie.name == cookie_name:
                return cookie.value

    def _get_google_signign(self):
        logger.info('trying to get google token for user: {}'.format(self.email))
        logger.debug('getting embedded info')
        azt, freq_token = self._get_embedded_info()
        logger.debug('sending lookup request')
        lookup_resp = self._lookup_request(azt, freq_token)
        logger.debug('sending request challenge')
        self._challenge_request(lookup_resp, azt)
        logger.debug('sending challenge consent')
        self._challenge_consent(lookup_resp, azt)

    def _get_google_token(self):
        logger.info('trying to get market token for user: {}'.format(self.email))
        first_sigin_data = {
            'ACCESS_TOKEN': '1',
            'Email': self.email,
            'Token': self._find_cookie(self._google_signin_cookiejar, 'oauth_token'),
            'add_account': '1',
            'androidId': self.androidId,
            'device_country': 'il',
            'droidguard_results': 'Cgb-t5ubwFXYAQHaB4kEAOuhCBJENRutwDUiK0HsxJC_ang6gO-dkkKYt3fVJ3ELaox-2TBqC3YFrtyO2WH_N8eVz0nymjftOnR3HubOYo1iSJO_x95FfZe1QmmnwgFYBMtgiLDrL4ofmyyQc_JevUZYCvR-M255_nRRB_l9bwHjWelpW1GMHi2xbrtmv0f-l9ufEPix96TNbBUYq2sHV5QA-x0AZPHbv3z5XBXcRLaV1SK1tcTvkQANwLL0nAGswCY_HAmf7GrPEKxC-UMNurGJfdLjOCW-4IDrqiJyKQulRSXHe_voUY8n1rQA9yEbFCgDGzCvYQ2Qzkwk_rz-hzFhoirYJT_BCAeKWOjtNcR4XhYredjE-eNPyITmaPC2yeSqr5GHlLKwEXydxBBLGqupeGu5F7sd4L4OrHvS_agYP19SYBBn6XKI0XC014NpSSoIX9RrfoxelZC68xGqN4gSAuizkfGIBw6NRot2bT8xHZ-QaslBSWb1WW8dEW2HRe_1PDvjuRzHBOieL39M17K_dGHUxZw2hNhVDKcZ56q3TR9kRENGzoI4HUeGTEfWchUFSxHVFzcLe48PCPAEd0RCaTkSrMNDTEIq2RNyjTdo3uM2H7nzkDJeBoXdNeni534_YwNI8p-V1Zr5eVwj-6jCPTtYVLoPJqjZ2_SUIiCF2WeB0ln2cUI_St9nNrbX2PYcBBu9Fq04YRoQCNSvs8_8_____wEQlN73COgB3qCPp_v_____AegB0qXVgPv_____AThrOEsSlyi0vRkgdEu1yYMvFywmJuCG_CJJtCcQfowftx-q3ylRkN9yiBPOo_hPDYAQ-TG60XPj3htaIf8_fxlz3SocT7qVdyX8G14n4gNX2--OfPz0yL2endbykvdnmEeTXLcrCtRcJtlwHIQuZrZT4XK7uPwDcFBIAnvkj9E1CaCbFHsMf6_k2h0mhM-7FhPcIEicIlpJN2U4tqjkTKw2xEle4gyCTKdv_EclMHQalVcM5Q4Ikf29zZaA47ISn5UKH8jRcf8tgXCjwPY7-PbUmc_w6fPEdvAU7WkXQL00r7AFC9rSEOe0bv5OmLXE6uEjA74UarHVCajt6qmCUUDfpmdOVtiBUQAbbUNY6paVUs_X32dTFmqxRp2JATBHodladYNw6PagO4W6OYBbdNB56Gqi1LwUpdaf4bj3oTXAuMvt-NyhenZdiLfwdejPEWkXYb8LIv9M_5e4sK-BlhOvM8s1YbXuI9tFz7pkrQjDIDUY9Pm7scG8TYMp0NylAepa8qBEHQTFgYs2xeUa8PI-sztliBET_9gfoTU-7wvrqHDgo74aUaA_NpOy18iEAaWjGYZ1h8YLbmGO4WbPiHGuw-QaV_esRUqQZodR3SczffCNh0jI1LANrOk-E7jiQ2FYArvyPQdAt-nNKOxtN9besvQvrSd8GffimouLqL-VjzicqRGr1WfJve0pPiLGRWPIcCpSRMBiI-PgVlflWu7Yl1pOGveTDFKL8WquRudaCmRMQqXwPJ05dTSoZf-yahAcRcu11gmoY1DFAcRgahFpp9OFj9keUFVFxeG5HcINB8hzORw_pOTp0hPszUIfB2Oq_Mxl8AEHxaHUOZYXDJvtKZkDsNB4VCcm9y7UvDzqu5HlkNHTN99w1RpXKy1JwA0Fjl3c25vZVq1XPJDJYA6FPDGtCgNYjXVYYqywosXpbWBCZwTBsJjPDywqeLO8ott0Nzl_0IwLRIp3EpELJNN_K8fl4s0D1WuDdDOnTLe7QzDa2qkF6qUmfGqhw_3ZXCMpbDh3ul50kLqth94Oxa9hNroMYtvqBeRm64Px92Uq9Mi2S3QFVyJD_13fu7pNlaOJH4aCiOXbv4XPQ_8vWYayeBYQPha1zWZmW7DVcmaYd_ZZFYksHv9vEkqE6RchPMfEeE_t61NBCZW94BvE1_JJUiZsJHOrXQOT1M6wg65DmSogyrQnjzMUZYZJYH6PDF9mg48jLXawJXPQXrkUNpG2yVZJlBCSSrXvStUzi1xVSXcc1c3bQx6UMxVWx87-vR_WRSwNc0bfhDIHn-9DtZqqAWL210bVbppkg8GOX5La_b33vjajU_lyUO2454qI7la8sBHny043bLyqo4Z4nZBp915bWZCjMCwETfl2felPcnP1UotUB6Qgj7m5tPtki-Nh6DRY8nG7I6wSd84oNAVzm8Qp8Ya9KsbENyiRr0Ybf7gLs6PkUzdE1G3gX7hv_aRpM9odcAdl7jw7E4d4wLPfdl4GljnLiQ36V_ITsnVSCNwPn9GHiAT7EeUC54AYPzTRFAKmvlCfc6iNM8dKl9H9Lff-JCEh9LTYqGLUyNk9ABOtWKfayWlLtacKlf92tyfcupMDHGTnOxddyEQbHV1Y7tIRF0IUL0UMIe0mVle_mLSVfAjQGEVsjxHVSDFoUIdllLYgrTcaixMSrIy3hrlgPwpsVJvkyf_FCgCF7DOFz91dQsZnYyyF1i_S5-KqvqhfWfUDWVi1fZEgR8kqyyxf4SAQQUtyH72EG570veuxYZp8cygJ2HsNIOvCzQMbrKQYa08CmO-zPT3jlP3DrfaawQ9Ty6zSwlgSo_8jy2H6HsHH58DKkliHMO8rj7_A2OM44WKgAXq4ppgJXaCN2BJLbKLYLLALW3ttvRateJ00nM39seuYlD9YPSyKdgHkMU0x8IbuhOTI5ayHvqzYCTAsyIEkIH5SVDo7XsUuo6vvrrpC8quKvtQXKNwRdjqrScFnJ2o4sFnPwGwLVnVA1_G2YdFIzJpg_P2tejiVy_1mOfUwrRoUq_ohnLuDvnu91IOZjrnO4-GHfo0OdmGIBl6lM6yAWvUZU7pwdy4rJ0-PCyT5PrL5vXSRB-C9icF-6AFm3Vn8cT74ATJxzIlLCFuNxQTw21Fb4XB8UfWJax52cWwPWEltvphcxXP-7H9WEZjp_SW73tKC64U9BhykqfgONUHTX2zXmZ1Oi41NmN9pu4hQN2nSgUEs0GGNLeQecILGVm3cnLFgNf2ZSsGJsgcbd8FyqIdrhUYuTVazvVmemNrNtx5PBvzHcSt9GhA5dBzMgTNVKnK-7jqnwXcFYKq2NyTj5MqvFfjgpD1mzcTIThmc5iWAF6vUOD9PDA04SwkGFAYQhPfoaedVeMo5uRAv6X8-vGpreTI4K3YYRIufSv9diegyQ90uGO8JrqoaR6Z-3I44lxIyiBqPPcfBBfWt8sGq_q42_3tPChyKn5drXblHTrpRV3rmlpDFCSiAuO1yjWI-8lC2GIumSpeCRpIfTWiE_60p0PKPuba-TJGm8RhUXty5D9IzA9GRHi62hmSHJu9mWM1eAG3yNtzZ6TMa2EBHg-poEhKwPgXejwoIsukvYjN_3xjorMhAuS15tGHTgTagoad03KDus-WKOjoBxNfp-RHifhpn-Zj7c601dggc3RUY39Jc7UQuo9lysA9K6goADG-2fpgnBC2rklxkbNNSpdTeiIYHlY4Gg7lnV5ZfYIumkKALzOmUit4pI4eWfdUygmLie4ad3aHjdyWyDr_2f9yi9brD-gWHNzzL6AFxZvrIVPgBXs9oK2tLIzGAzEHWJYUM3n5ZqDA1U38haxZ2MxyAqyjrPXCppIG92CuDGfl0mi5V47OV7Vd-RMKyeVn9YLeC4_32Ff9lMxKWc9-G4AMicjGZlix2uAWiccRVrRa53t8yYjhXT0_NqOYGrJV-rXoZEOZCIghRl5E6c7aZOFZugB7N4XJCihTpXhDtHks3KIf0YhyMyXviJZNP-GzVy2oHK-KibMqicfHOdvoiRH0XjdhS0DNK8MrMkDDViMjkd3CLF0XRKrDlAZPtbyaSLVgIOPeU05C_vBhmcf3rIB5qNRsmezqZgiplbTLMOPbHDz7CTGRs3U7vw3wTa6okso9afczpirAgSGhc53cRBx-EWs-EtZfVDGzzQfLviOiUmCTAC7Jk6QrbT9saY3x2k-6E0NwwjdoBKYo--BQOGXJ0hVgNtLnoKoQJy9wFKIaA65SeqwrJLA9iD_fy8tUdb3rX1Vuc8zpmD303WvJycioxiuRQROggmQPasYCJoYl2KQu-LNJBAtnOEra7gH9HZnPOkJJgfAneuUf5c5GkZIYn_7yd82NscI2zhCBUKcaYJ0iSayLoxagH97YFXbT-z8AUMfhpjY7moKFM0i26aB45VEdW-UXV_OR8fNgOsyj_SKH2zWPg9eK3vC2dp10y05UL8RQzNAW8KjvExrUu1Oj-Efqx53br2Y-dXCnfdh63TIXFlxLqcRSOTMd0Gf7KBE_vNS_hJ6KeyiEVm0rA1_ONpVxWdTFByXrqcycA5LNI45ZmK0iH9rOVde86y_zsvsts10_wjbzfNSqBVuD1tIOWDYoxD2S3lcoxLdOKGmGRcPRQeXlsDc18ubs20X243UfWbWn2r5FC92Mh7Jx7rM1xkpc4D_2jnmv5RAf4_CKU_xWUcXW6whny-_rfq22s9vtSVlQjmaqH1h9fHilldokJJRV8zG50EFhOc2GlbK9ta_HCsWd_BAgjOsRqCa_O1Y1TfskM_eNgqNwG-omOKiCWnSsq_FKk_5OZfdclIs5-cOMb_zyCT82Y2uqTdqLOjGVeTEtqSoUgl4qflHBLU5HQKJZCdHFUEt3Fyc0Qa-ptSATKPfva3IiodAJZ8wboMDkC3MBUQ87rj1PZv1mJELfonEJ4UvLM1h_8jkvTcSOPelSFp7p6JcH6aqHKacgj1dJL8ERSNb6JxMutQjUbCQ5WfzKQOIbTel3DCV3R4TBlm69nFvzdMCwQ7Ett3wLAjD7pfYFzzJlJd0N7wZgi9BJI8S3vByjXVfUT3D2GosaCV7EZMBdDRU16AjsPVKo8FcUZFbZe-nDtCACOZCA9BILjt2KbtGCTJaU3VOtcffY6Z_p0OX3eADMETqN5XiPXXykb6y0mbZZRzZJtvSJC5OFzTYlrD4As3wi9u9u0cKGEHyeI-JNmPdp2Kml83UxzbibI53noJg1imCfxbUoYalloScQapzNnBNDheLUvRBGTCxZJhT6cpA-41QferO-sFUQVLMGiHg_Sys71lT6C9W-fwjX7kxkcCPEcoFQ157npfLrFYY39DPoLoRaXD_36PzTqQ2sPuBuLz8B1SaPKXTKMDoDiywpS7lqbpeuXz01zSkfXcgXMgeIjeAjq6SekXjKjOBchlU30r8hUbWT2dXrsQ8vGB0TTcU4l5zw2ce3O2IXVuECK0WcCmQGoLSrO97-Wd0LuQQDUqy3ddnvkochYJ4G7IuqVxiZ6-7dPPqgnyyRx0OcoQBwqAjspambhLjKmJl4aL2hrkQclAm2T4eFJ0VTfNlefGtGEl4IGPC5E4kQ0gQ9RD5XTWRChAt6l2ZsfskFOI9TRjMc5Jcd3wWXi1L9sJOXsq5GcoGhdwyfhDPilTKsyAXNJ-cqETPz23w3qk3ow-wGC2304OxiIDt6r4_vCXPtaWueTPuu6V9_swOYUCAhy-XVzqfkRmCjGndwcqsJkRmSpiyixAkVcMNBTtRvgpWdG2h9j9b_884WgSszWEe3vxsI0F1cFnvQHhS7uFUnjCFwsTL2aJzPYl_dcN6aXaw7XVDQBoFdybwioNyEQhnxP_jgaJz56qCByOKpODks6tdhwjSnubyVCASDLzbDEAcVXNPRLdJVjyABVAqw9ads4egW63PlQFru99H7ZrrPZIxFxIsVmNd9prXlBu9OX4FktzpCPfNyXE_s6BBV8TyaCceOTGt9UpEgVnfHJB7O-s2lo7cAoscxeRZWUHNwX0b3smxczV_qFJ3sismA05UH-ZfreEfekBnt-Iw4ByjIW1N47Pgvja0w30E5ct531OrCSL5_0507Jm2eGeGWovl659qKVBxVrG6VvWxJEHWrTZGCx7k-b_tIJz7CTMbbPnmAWcAgAGWhKp1JTGAAvL9lEIU4wSSpt2YGv0GQNhK79toJzE_oGszNv-uCYtq7AxMWWj8aLfxBQk2ceEcHZpvNf2VfKa_3zOna4VuxX5I1F-cVKD0lq3tHnnX-JNY43QPEq2jWY8kvzUI2MCqXnyLX0yp3WZRKZWW73ZIzSsVS3jC6op38xNON7MHfrVeXlLZDeNSJcKPEt6cNzpqaqKZBfYUbpneVB8cS117JCIcdNbcxW4RfYsiT3GSHgRWRKgXQ2GBVBhh3_FVDv9Py125yE-C_gnEBtO7ucimHhIbMgG9GAuNkIP95XhUlP8oqjkl9tqh7RkNVr5_IVJcwafCrO7QtYJ1b1eTKTSPkEw5nTxEGpcSAofHSLbjip_3UHwWlZA8M9W7ZKlSVoduxqoCvcC6MFnQYmvPIvumPcMIFUtqvCg6J3fIj1ehtQe4uPkLnN718-gRg4Ow-tX_EcrxGTAF2bMwiuqIt9JCtMmpgj3DFwnIgpe5LA50tQqCcx7OnQ--itL7wxLeerEuE87VsACg_aq3eHWllWafEkUY5PB-EzLDoOP41FucJPd8PtGGlgfIP-YyCNqwbKd8zG8TGP5MGMIp7IyHmP5yVOyiZl-qCUava-zpFVGGRiP3nww-guEUITB0Bs6OoJHULhxPWTn1Bv1G_ZtfDDX23ZMpi1wVZYVSkNluw7Q1g5DJEPD8VJHNaygTdIygqCUKHPXZ-CaQ0UwhnHbaCjaF93VKh7n5YthF0zO7WbIpLegRm3D4UPDma3Rbb5F0kgAvj1SVTzxUeZQOW6JKI8ALqlJtDlUjTyRsjtgyl-jm_I6KP8PIq12nPDb5YO3xt_TXtfbidL6t2t0PDtwJ0iUfyUaQgmYYQHh4ZMLuNlFnQJbqaUyMrXs16FXcYD8Er_X2S6GnKq1xuxTV9Ef9tOFsZt3FZy5_6JVaZ9L2S6jDauY83VVAxziDjrtM3sqYem46VRMtejHW3CJOgM3Bjw14g1xUZAs8jrOG7-PHFh2tgAX4Ku4mBOJAD3s8mi5v9_KQSwo_BHHdzBJZ0mI6_WeZVevkwnASprVvpcAidY66YJ5KhdGN7-f-fAPRIA30MYcs-E7S_RTGRxuno7iS4SQvYD-MbWbvszEJ7Y-TRziO77YsnSF23qsZ5rwweYoenaVI2yg-ihwtEnofCGIWy7XPDiZ-xin-uuC70G48ljKl-yD_CVJUaZzNtg5Y83sZ69NI35J6pKVOCJYn0mkZXgt-oBim37icKAn_h6YeTJK3opPQKssqm-XEbi717XuiRflP0RoTF_3hEgG9kXqtGoKPsJyKrtdt-omo3-eVsB7aRjdV0J_IMuZotXT0yWa2OX-wYsF0Z06osGZCi3Q4oBnkSip60DwMXsFkAb1Gaq0d7dovGkTApFZHxhjeVJDnksNrUzaFcN703zqfPYW8tJru-Merqxxc4jfJzRZsQGaFtYEwS63wyjeW011EaLhj-cQGDChgi8H5nrIPb0ra2nDcqLhTOm_ojgeIGRmJRx7WoPT21xrFmPEXg1zTjpFPXspG0XNOSbE0iU_ZUf5gjAeYLVIPStHj1tVgLAEnZSc2ikKEHDENzhMeZDHhSM4zOmMpTDq12LREe5wFHOGYB15321_mR2HdVf74l0NV20ozFbf69j8Bb9ixNL3gX_vU_eHptUvxcd0Drb7YQY1CdBkTDZJbzRr8fW',
            'google_play_services_version': '%s' % self.GMS_CORE_VERSION,
            'lang': 'en_US',
            'sdk_version': self.SDK_VERSION,
            'service': 'ac2dm'}

        self._android_auth_session.addheaders = {
            'Accept-Encoding': 'gzip',
            'Connection': 'Keep-Alive',
            'User-Agent': 'GoogleAuth/1.4 (klte MMB29M); gzip',
            'app': 'com.google.android.gms',
            'content-type': 'application/x-www-form-urlencoded',
            'device': self.androidId
        }.items()

        try:

            resp = self._android_auth_session.open('https://android.clients.google.com/auth',
                                                   data=urllib.urlencode(first_sigin_data))
        except urllib2.HTTPError as e:
            logger.error('{}'.format(e))
            logger.error('login failed, oauth_token cookie: {}'.format(self._find_cookie(
                self._google_signin_cookiejar, 'oauth_token')))
            raise LoginError('google login failed')

        resp_text = _get_resp_content(resp)
        bad_format_lines = [line for line in resp_text.splitlines() if '=' not in line and line]
        if bad_format_lines:
            logger.warning('bad format lines')
            logger.info('response lines: {}'.format(resp_text.splitlines()))
        # if line is for us to ignore empty lines
        resp_dict = {line.split('=')[0]: line.split('=')[1] for line in resp_text.splitlines() if line}
        return resp_dict['Token']

    def _get_android_auth_token(self):
        androidmarket_service_post_data = {'Email': self.email,
                                           'Token': self.google_token,
                                           '_opt_is_called_from_account_manager': '1',
                                           'androidId': self.androidId,
                                           'app': 'com.android.vending',
                                           'callerPkg': 'com.google.android.gms',
                                           'callerSig': '38918a453d07199354f8b19af05ec6562ced5788',
                                           'check_email': '1',
                                           'client_sig': '38918a453d07199354f8b19af05ec6562ced5788',
                                           'device_country': 'us',
                                           'google_play_services_version': '%s' % self.GMS_CORE_VERSION,
                                           'is_called_from_account_manager': '1',
                                           'lang': 'en_US',
                                           'sdk_version': '%s' % self.SDK_VERSION,
                                           'service': 'androidmarket',
                                           'system_partition': '1',
                                           'token_request_options': 'CAA4AQ=='}

        self._android_auth_session.addheaders = {'Accept-Encoding': 'gzip',
                                                 'Connection': 'Keep-Alive',
                                                 'User-Agent': 'GoogleAuth/1.4 '
                                                               '(klte '
                                                               'MMB29M); '
                                                               'gzip',
                                                 'app': 'com.android.vending',
                                                 'content-type': 'application/x-www-form-urlencoded',
                                                 'device': self.androidId}.items()

        try:
            resp = self._android_auth_session.open('https://android.clients.google.com/auth',
                                                   data=urllib.urlencode(androidmarket_service_post_data))
            resp_text = _get_resp_content(resp)
            resp_dict = {line.split('=')[0]: line.split('=')[1] for line in resp_text.splitlines() if line}
            return resp_dict['Auth']

        except urllib2.HTTPError as e:
            logger.error('{}'.format(e), exc_info=True)
            logger.error('google token probably expired, please try to regain token')
            raise GoogleTokenExpired('token is expired')


def _get_resp_content(resp):
    data = resp.read()
    if resp.info().get('content-encoding') == 'gzip':
        return zlib.decompress(data, 16 + zlib.MAX_WBITS)
    return data
