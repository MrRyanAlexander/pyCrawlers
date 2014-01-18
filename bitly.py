import requests
import json

query_params = {'access_token': 'API_KEY',
                'link': 'http://bitly.com/RYYpZT', 'unit' : 'minute', 'units' : 15} 

endpoint = 'https://api-ssl.bitly.com/v3/link/clicks'
response = requests.get(endpoint, params= query_params)

data = json.loads(response.content)
print data['data']['link_clicks']