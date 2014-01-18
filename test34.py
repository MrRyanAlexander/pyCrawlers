#page spider
import urlparse
import urllib
from bs4 import BeautifulSoup

url = "http://losangeles.craigslist.org/sof/"

urls = [url] #stack of urls to scrape
visited  = [url] #historic record of urls 

while len(urls) >0:
    try:
	htmltext = urllib.urlopen(urls[0]).read()
    except:
	print urls[0]
    soup = BeautifulSoup(htmltext)

    urls.pop(0)

    print soup.findAll('span.pl a',href=True)
 #   print len(urls)

#	tag['href'] = urlparse.urljoin(url,tag['href'])
#    for tag in soup.findAll('a',href=True):
#	if url in tag['href'] and tag['href'] not in visited:
#	    urls.append(tag['href'])
#	    visited.append(tag['href'])
#
#print visited



