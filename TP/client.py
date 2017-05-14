import json
import urllib.request
import urllib.parse
import urllib.error

class ServerError(Exception):
    def __init__(self, code=None, msg=None):
        self.code = code
        self.msg = msg


class Connection:
    def __init__(self, base_url="http://pac.fil.cool/uglix"):
        self.base = base_url
        self.session = None

    def _post_processing(self, result, http_headers):
        if http_headers['Content-Type'] == "application/json":
            return json.loads(result.decode())
        if http_headers['Content-Type'].startswith("text/plain"):
            return result.decode()
        return result

    def _query(self, url, request, data=None):
        try:
            if self.session:
                request.add_header('Cookie', self.session)
            with urllib.request.urlopen(request, data) as connexion:
                headers = dict(connexion.info())
                result = connexion.read()
            
            if 'Set-Cookie' in headers:
                self.session = headers['Set-Cookie']

            return self._post_processing(result, headers)

        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
            message = e.read()
            raise ServerError(e.code, self._post_processing(message, headers)) from None
          
    
    def get(self, url):
        request = urllib.request.Request(self.base + url, method='GET')
        return self._query(url, request)


    def post(self, url, **kwds):
        request = urllib.request.Request(self.base + url, method='POST')
        data = None
        if kwds:     
            request.add_header('Content-type', 'application/json')
            data = json.dumps(kwds).encode()
        return self._query(url, request, data)


    def put(self, url, content):
        request = urllib.request.Request(self.base + url, method='PUT')
        if isinstance(content, str):
            content = content.encode()
        return self._query(url, request, data=content)


    def post_raw(self, url, data, content_type='application/octet-stream'):
        request = urllib.request.Request(self.base + url, method='POST')
        request.add_header('Content-type', content_type)
        return self._query(url, request, data)

    def close_session(self):
        self.session = None