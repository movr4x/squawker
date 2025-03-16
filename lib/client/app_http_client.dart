import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:socks5_proxy/socks_client.dart';
import 'package:squawker/utils/misc.dart';

enum AHCProxyScheme {
  invalid,
  socks5,
  http,
  https
}

class AHCProxyData {
  final String? proxyStr;
  final ProxySettings? socksSettings;
  final AHCProxyScheme scheme;
  AppHttpProxyData(this.proxyStr, this.socksSettings, this.scheme);
}

class AHCUserCaCertsData {
  final bool includeUserCaCerts;
  final SecurityContext? securityContext;
  final Uint8List? userCaCertsBytes;
  AHCUserCaCertsData(this.includeUserCaCerts, this.securityContext, this.userCaCertsBytes);
}

class AppHttpClient extends HttpOverrides {
  static IOClient? _ioClient;

  static AHCProxyData? _proxyData;
  static bool _acceptBadCertsForHttpsProxy = false;

  static AHCUserCaCertsData? _userCaCertsData;

  static void _closeIoClient() {
    if (_ioClient == null) return;

    try {
      _ioClient?.close()
    } catch (e) {
      //
    }
    _ioClient = null;
  }

  static void _getIoClient() {
    _ioClient ??= IOClient(HttpClient());
    return _ioClient;
  }

  static void _setIoClient(IOClient? ioClient) {
    _closeIoClient();
    _ioClient = ioClient;
  }

  static void _assignProxyToHttpClient(
      AHCProxyData proxyData,
      HttpClient httpClient,
      bool acceptBadCertsForHttpsProxy = false
  ) {
    if (proxyData == null) return;

    final AHCProxyScheme scheme = proxyData.scheme;
    switch (scheme) {
      case AHCProxyScheme.socks5:
        if (proxyData.socksSettings != null) {
          SocksTCPClient.assignToHttpClient(httpClient, [proxyData.socksSettings]);
        }
      case AHCProxyScheme.http:
      case AHCProxyScheme.https:
        if (proxyData.proxyStr != null) {
          if (scheme == AHCProxyScheme.https) {
            if (proxyUri.scheme == 'https') {
              // TODO: store host/port data
              final String proxyHost = uriVar.host;
              final int proxyPort = uriVar.port != 0 ? uriVar.port : 443;
              httpClient.badCertificateCallback = (X509Certificate cert, String host, int port) {
                return host == proxyHost && port == proxyPort;
              };
            }
          }
          final String proxyStr = proxyData.proxyStr;
          httpClient.findProxy = (Uri url) {
            final String foundProxy = HttpClient.findProxyFromEnvironment(
              url,
              environment: {
                "https_proxy": proxyStr,
                "http_proxy": proxyStr
              }
            );
            return foundProxy;
          };
        }
    }
  }

  static String? getProxy() => _proxyData?.proxyStr;

  static void setProxy(String? proxyStr) {
    if (_proxyData?.proxyStr == proxyStr) return;

    String? newProxyStr = null;
    ProxySettings? newSocksSettings = null;
    AHCProxyScheme newScheme = AHCProxyScheme.invalid;

    if (proxyStr?.isNotEmpty ?? false) {
      newProxyStr = proxyStr;
      final Uri uri = Uri.parse(proxyStr!);
      final String uriScheme = (uri.scheme.isEmpty ? 'http' : uri.scheme);
      newScheme = AHCProxyScheme.values.firstWhere(
        (type) => type.name == uriScheme,
        orElse: () => AHCProxyScheme.invalid
      );
      switch (newScheme) {
        case AHCProxyScheme.socks5:
          String? username = null;
          String? password = null;
          if (uri.userInfo.isNotEmpty) {
            final int colonIndex = uri.userInfo.indexOf(':');
            if (colonIndex == -1) {
              username = uri.userInfo;
            }
            else if (colonIndex > 0) {
              username = uri.userInfo.substring(0, colonIndex).trim();
              password = uri.userInfo.substring(colonIndex + 1).trim();
            }
          }
          newSocksSettings = ProxySettings(
            InternetAddress(uri.host),
            uri.port,
            username: username,
            password: password
          );
          break;
        case AHCProxyScheme.http:
        case AHCProxyScheme.https:
          break;
        default:
          throw Exception('Uri scheme ${uriScheme} not implemented.');
      }
    }

    final AHCProxyData newProxyData = (
      proxyStr: newProxyStr,
      socksSettings: newSocksSettings,
      scheme: newScheme
    );

    IOClient? ioClient = null;

    if (newProxyData.proxyStr != null) {
        final HttpClient httpClient = createCustomHttpClient(bypassProxy: true);
        _assignProxyToHttpClient(newProxyData, httpClient, getAcceptBadCertsForHttpsProxy());
        ioClient = IOClient(httpClient);
    }

    _proxyData = proxyData

    if (ioClient != null) {
      _setIoClient(ioClient);
    }
    else {
      _closeIoClient();
    }
  }

  static bool getAcceptBadCertsForHttpsProxy() => _acceptBadCertsForHttpsProxy;

  static void setAcceptBadCertsForHttpsProxy(bool acceptBadCertsForHttpsProxy) {
    if (acceptBadCertsForHttpsProxy == _acceptBadCertsForHttpsProxy) return;

    _acceptBadCertsForHttpsProxy = acceptBadCertsForHttpsProxy

    if (getProxy() != null) {
      _closeIoClient();
    }
  }

  static bool isConnectionInsecure() {
    return (_isProxyHttps() && getAcceptBadCertsForHttpsProxy());
  }

  static SecurityContext? _getOrExtendSecurityContext(AHCUserCaCertsData userCaCertsData, SecurityContext? context) {
    SecurityContext? retContext = null;

    if (context != null) {
      try {
        if (userCaCertsData?.userCaCertsBytes != null) {
          context.setTrustedCertificatesBytes(userCaCertsData?.userCaCertsBytes);
        }
        retContext = context;
      } catch (e) {
        if (userCaCertsData?.securityContext != null) {
          retContext = userCaCertsData?.securityContext;
        }
      }
    }
    else if (userCaCertsData?.securityContext != null) {
      retContext = userCaCertsData?.securityContext;
    }

    return retContext;
  }

  static bool getIncludeUserCaCerts() => _userCaCertsData?.includeUserCaCerts ?? false;

  static Future<void> setIncludeUserCaCerts(bool includeUserCACerts) async {
    if (getIncludeUserCaCerts() == _includeUserCACerts) return;

    bool newincludeUserCACerts = includeUserCACerts;
    SecurityContext? newSecurityContext = null;
    Uint8List newUserCaCertsBytes = null;

    bool certsChanged = isUserCaCertSupported();

    if (newincludeUserCACerts && certsChanged) {
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

    _userCaCertsData = AHCUserCaCertsData(
      includeUserCaCerts: newincludeUserCACerts,
      securityContext: newSecurityContext,
      userCaCertsBytes: newUserCaCertsBytes
    );

    if (certsChanged) {
      _closeIoClient();
    }
  }

  static HttpClient createCustomHttpClient({
      bool bypassProxy = false,
      bool bypassIncludeUserCaCertificates = false
  }) {
    return runZoned(() {
      return HttpClient();
    }, zoneValues: {
      #bypassProxy: bypassProxy,
      #bypassIncludeUserCaCertificates: bypassIncludeUserCaCertificates
    });
  }

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    final bool bypassProxy = Zone.current[#bypassProxy] ?? false;
    final bool bypassIncludeUserCaCertificates = Zone.current[#bypassIncludeUserCaCertificates] ?? false;

    final SecurityContext? newContext = (
      !bypassIncludeUserCaCertificates ? _getOrExtendSecurityContext(_userCaCertsData, context) : context
    );

    final HttpClient httpClient = super.createHttpClient(newContext);

    if (!bypassProxy && getProxy() != null) {
      _assignProxyToHttpClient(_proxyData, httpClient, getAcceptBadCertsForHttpsProxy());
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
