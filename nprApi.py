from urllib2 import urlopen
from json import load 

url = 'http://api.npr.org/query?apiKey=' 
key = 'API_KEY'
url = url + key
url += '&numResults=3&format=json&id='
url += raw_input("Which NPR ID do you want to query?")

response = urlopen(url)
json_obj = load(response)

for story in json_obj['list']['story']:
	print story['title']['$text'] 	