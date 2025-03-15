import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:socks5_proxy/socks_client.dart';
import 'package:squawker/utils/misc.dart';

class AppHttpClient extends HttpOverrides {
  static IOClient? _ioClient;

  static String? _proxy;
  static ProxySettings? _proxySettings;
  static bool _isProxyHttps = false;
  static bool _isProxyModified = false;

  static bool _acceptBadCertsForHttpsProxy = false;

  static bool _includeUserCaCerts = false;
  static SecurityContext? _securityContext;
  static Uint8List? _userCaCertsBytes;

  static void _closeIoClient() {
    if (_ioClient == null) return;

    try {
      _ioClient?.close()
    } catch (e) {
      //
    }
    _ioClient = null;
  }

  static void _setIoClient(IOClient? ioClient) {
    _closeIoClient();
    _ioClient = ioClient;
  }

  static void _getIoClient() {
    _ioClient ??= IOClient(HttpClient());
    return _ioClient;
  }

  static void _isProxyModified() => _isProxyModified;

  static void _isProxyHttps() => _isProxyHttps;

  static void _assignProxyToHttpClient(String? proxy, ProxySettings? proxySettings, HttpClient httpClient) {
    if (proxySettings != null) {
      SocksTCPClient.assignToHttpClient(httpClient, [proxySettings]);
    }
    else if (proxy != null) {
      httpClient.findProxy = (Uri url) {
        final String foundProxy = HttpClient.findProxyFromEnvironment(
          url,
          environment: {"https_proxy": proxy}
        );
        return foundProxy;
      };
    }
  }

  static void setProxy(String? proxy) {
    if (proxy == _proxy) return;

    _isProxyModified = true;

    String? newProxy = null;
    ProxySettings? newProxySettings = null;
    bool newIsProxyHttps = false;

    IOClient? ioClient = null;

    if (proxy?.isNotEmpty ?? false) {
      newProxy = proxy;
      try {
        final Uri uri = Uri.parse(proxy!);
        HttpClient? httpClient = null;
        if (uri.scheme == 'socks5') {
          String? username = null;
          String? password = null;
          if (uri.userInfo.isNotEmpty) {
            final int userInfoSplitIndex = uri.userInfo.indexOf(':');
            if (userInfoSplitIndex == -1) {
              username = uri.userInfo;
            }
            else {
              username = uri.userInfo.substring(0, userInfoSplitIndex);
              password = uri.userInfo.substring(userInfoSplitIndex + 1);
            }
          }
          newProxySettings = ProxySettings(
            InternetAddress(uri.host),
            uri.port,
            username: username,
            password: password
          );
          httpClient = HttpClient();
          _assignProxyToHttpClient(newProxy, newProxySettings, httpClient);
        }
        else if (uri.scheme.isEmpty || uri.scheme == 'http' || uri.scheme == 'https') {
          newIsProxyHttps = true;
          httpClient = HttpClient();
          _assignProxyToHttpClient(newProxy, newProxySettings, httpClient);
        }
        else {
          throw Exception('Uri scheme ${uri.scheme} not implemented.');
        }
        if (httpClient != null) {
          ioClient = IOClient(httpClient);
        }
      } catch (e) {
        _isProxyModified = false;
        rethrow;
      }
    }

    _proxy = newProxy;
    _proxySettings = newProxySettings;
    _isProxyHttps = newIsProxyHttps;

    if (ioClient != null) {
      _setIoClient(ioClient);
    }
    else {
      _closeIoClient();
    }

    _isProxyModified = false;
  }

  static String? getProxy() => _proxy;

  static void setAcceptBadCertsForHttpsProxy(bool acceptBadCertsForHttpsProxy) {
    if (acceptBadCertsForHttpsProxy == _acceptBadCertsForHttpsProxy) return;

    _acceptBadCertsForHttpsProxy = acceptBadCertsForHttpsProxy

    if (getProxy() != null) {
      _closeIoClient();
    }
  }

  static bool getAcceptBadCertsForHttpsProxy() => _acceptBadCertsForHttpsProxy;

  static SecurityContext? _getOrExtendSecurityContext(SecurityContext? context) {
    SecurityContext? retContext = null;
    if (context != null) {
      try {
        if (_userCaCertsBytes != null) {
          context.setTrustedCertificatesBytes(_userCaCertsBytes);
        }
        retContext = context;
      } catch (e) {
        if (_securityContext != null) {
          retContext = _securityContext;
        }
      }
    }
    else if (_securityContext != null) {
      retContext = _securityContext;
    }
    return retContext;
  }

  static Future<void> setIncludeUserCaCerts(bool includeUserCACerts) async {
    if (includeUserCACerts == _includeUserCACerts) return;

    SecurityContext? newSecurityContext = null;
    Uint8List newUserCaCertsBytes = null;

    bool certsChanged = isUserCaCertSupported();

    if (includeUserCaCerts && certsChanged) {
      final List<String> pemCerts = (await getUserCaCerts()) ?? [];
      if (!pemCerts.isEmpty) {
        newSecurityContext = SecurityContext(withTrustedRoots: true);
        final String pemCertsCombined = pemCerts.map((pem) => pem.trim()).join('\n');
        newUserCaCertsBytes = utf8.encode(pemCertsCombined);
        newSecurityContext.setTrustedCertificatesBytes(newUserCaCertsBytes);
      } else {
        certsChanged = false;
      }
    }

    _includeUserCaCerts = includeUserCaCerts;
    _securityContext = newSecurityContext;
    _userCaCertsBytes = newUserCaCertsBytes;

    if (certsChanged) {
      _closeIoClient();
    }
  }

  static bool getIncludeUserCaCerts() => _includeUserCaCerts;

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    fianl SecurityContext? newContext = _getOrExtendSecurityContext(context);
    final HttpClient httpClient = super.createHttpClient(newContext);
    if (!_isProxyModified() && getProxy() != null) {
      _assignProxyToHttpClient(_proxy, _proxySettings, httpClient);
      if (_isProxyHttps() && getAcceptBadCertsForHttpsProxy()) {
        httpClient.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
      }
    }
    return httpClient;
  }

}

class AppHttpClientLegacy {

  static Future<HttpClient>? _httpClient;
  static Future<IOClient>? _ioClient;

  static Future<HttpClient> _createHttpClient() async {
    if (isUserCACertSupported()) {
      final List<String> pemCerts = (await getUserCACerts()) ?? [];
      if (!pemCerts.isEmpty) {
        try {
          final securityContext = SecurityContext(withTrustedRoots: true);
          final pemCertsCombined = pemCerts.map((pem) => pem.trim()).join('\n');
          final pemCertsBytes = utf8.encode(pemCertsCombined);
          securityContext.setTrustedCertificatesBytes(pemCertsBytes);
          return HttpClient(context: securityContext);
        } catch (e) {
          //
        }
      }
    }
    return HttpClient();
  }

  static Future<HttpClient> _getNewHttpClient() {
    if (_ioClient != null) {
      _ioClient?.then(
        (ioClient) {
          try {
            ioClient.close();
          } catch (e) {
            //
          }
        }
      );
      _ioClient = null;
    }
    else if (_httpClient != null) {
      _httpClient?.then(
        (httpClient) {
          try {
            httpClient.close(force: true);
          } catch (e) {
            //
          }
        }
      );
    }
    _httpClient = _createHttpClient();
    return _httpClient!;
  }

  static Future<HttpClient> _getCachedHttpClient() {
    _httpClient ??= _createHttpClient();
    return _httpClient!;
  }

  static Future<IOClient> _createIOClient() async {
    HttpClient httpClient = await _getCachedHttpClient();
    return IOClient(httpClient);
  }

  static Future<IOClient> _getCachedIOClient() {
    _ioClient ??= _createIOClient();
    return _ioClient!;
  }

  static Future<void> setProxy(String? proxy) async {
    if (proxy?.isEmpty ?? true) {
      await _getNewHttpClient();
      return;
    }
    Uri uri = Uri.parse(proxy!);
    HttpClient httpClient;
    if (uri.scheme == 'socks5') {
      httpClient = await _getNewHttpClient();
      String? username;
      String? password;
      if (uri.userInfo.isNotEmpty) {
        List<String> userPwdLst = uri.userInfo.split(':');
        username = userPwdLst[0];
        if (userPwdLst.length > 1) {
          password = userPwdLst[1];
        }
      }
      SocksTCPClient.assignToHttpClient(httpClient, [
        ProxySettings(InternetAddress(uri.host), uri.port, username: username, password: password),
      ]);
    }
    else if (uri.scheme.isEmpty || uri.scheme == 'http' || uri.scheme == 'https') {
      httpClient = await _getNewHttpClient();
      httpClient.findProxy = (Uri url) {
        String foundProxy = HttpClient.findProxyFromEnvironment(url, environment: {"https_proxy": proxy});
        return foundProxy;
      };
    }
    else {
      throw Exception('Uri scheme ${uri.scheme} not implemented.');
    }
    if (!isUserCACertSupported()) {
      // This allows bad certificates, and is not secure.
      // If user supplied CA certificates are supported then it should not
      // be used, as user can simply add CA cert for proxy.
      httpClient.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
    }
  }

  static Future<http.Response> httpGet(Uri url, {Map<String,String>? headers}) async {
    return (await _getCachedIOClient()).get(url, headers: headers);
  }

  static Future<http.Response> httpPost(Uri url, {Map<String,String>? headers, Object? body, Encoding? encoding}) async {
    return (await _getCachedIOClient()).post(url, headers: headers, body: body, encoding: encoding);
  }

  static Future<http.StreamedResponse> httpSend(http.Request request) async {
    return (await _getCachedIOClient()).send(request);
  }

}
