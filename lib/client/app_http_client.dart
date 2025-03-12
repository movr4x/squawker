import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:socks5_proxy/socks_client.dart';

class AppHttpClient {

  static HttpClient? _httpClient;
  static IOClient? _ioClient;

  static HttpClient _getHttpClient() {
    _httpClient ??= HttpClient(context: SecurityContext(withTrustedRoots: true));
    return _httpClient!;
  }

  static IOClient _getIOClient() {
    _ioClient ??= IOClient(_getHttpClient());
    return _ioClient!;
  }

  static void setProxy(String? proxy) {
    if (proxy?.isEmpty ?? true) {
      _ioClient = null;
      return;
    }
    Uri uri = Uri.parse(proxy!);
    HttpClient httpClient;
    if (uri.scheme == 'socks5') {
      httpClient = _getHttpClient();
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
      httpClient = _getHttpClient();
      httpClient.findProxy = (Uri url) {
        String foundProxy = HttpClient.findProxyFromEnvironment(url, environment: {"https_proxy": proxy});
        return foundProxy;
      };
    }
    else {
      throw Exception('Uri scheme ${uri.scheme} not implemented.');
    }
    // With network_security_config.xml allowing user supplied certs for SecurityContext, user can
    // simply add certificate for proxy, so accepting invalid certs should not be needed anymore.
    //httpClient.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }

  static Future<http.Response> httpGet(Uri url, {Map<String,String>? headers}) async {
    return _getIOClient().get(url, headers: headers);
  }

  static Future<http.Response> httpPost(Uri url, {Map<String,String>? headers, Object? body, Encoding? encoding}) async {
    return _getIOClient().post(url, headers: headers, body: body, encoding: encoding);
  }

  static Future<http.StreamedResponse> httpSend(http.Request request) async {
    return _getIOClient().send(request);
  }

}
