import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:socks5_proxy/socks_client.dart';
import 'package:squawker/utils/misc.dart';

class AppHttpClient {

  static Future<HttpClient>? _httpClient;
  static Future<IOClient>? _ioClient;

  static Future<HttpClient> _createHttpClient() async {
    final List<String> pemCerts = (await getUserCerts()) ?? [];
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
    return HttpClient();
  }

  static Future<HttpClient> _getNewHttpClient() {
    if (_ioClient != null) {
      try {
        _ioClient.close();
      } catch (e) {
        //
      }
      _ioClient = null;
    }
    else if (_httpClient != null) {
      try {
        _httpClient.close(force: true);
      } catch (e) {
        //
      }
    }
    _httpClient = _createHttpClient();
    return _httpClient;
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
    final httpClient = await _getNewHttpClient();
    if (proxy?.isEmpty ?? true) {
      return;
    }
    Uri uri = Uri.parse(proxy!);
    if (uri.scheme == 'socks5') {
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
      httpClient.findProxy = (Uri url) {
        String foundProxy = HttpClient.findProxyFromEnvironment(url, environment: {"https_proxy": proxy});
        return foundProxy;
      };
    }
    else {
      throw Exception('Uri scheme ${uri.scheme} not implemented.');
    }
    // With user supplied certs for SecurityContext, user can simply add certificate
    // for proxy, so accepting invalid certs should not be needed anymore.
    //httpClient.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
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
