class MySpider(CrawlSpider):
 
name = 'MySpider'
allowed_domains = ['somedomain.com', 'sub.somedomain.com']
start_urls = ['http://www.somedomain.com']
 
rules = (
    Rule(SgmlLinkExtractor(allow=('/pages/', ), deny=('', ))),
 
    Rule(SgmlLinkExtractor(allow=('/2012/03/')), callback='parse_item'),
)
 
def parse_item(self, response):
    contentTags = []
 
    soup = BeautifulSoup(response.body)
 
    contentTags = soup.findAll('p', itemprop="myProp")
 
    for contentTag in contentTags:
        matchedResult = re.search('Keyword1|Keyword2', contentTag.text)
        if matchedResult:
            print('URL Found: ' + response.url)
 
    pass
       
a = open("test.py")
from compiler import compile
d = compile(a.read(), 'spider.py', 'exec')
eval(d)
 
MySpider
<class '__main__.MySpider'>
print MySpider.start_urls
['http://www.somedomain.com']
       
class MySpider(CrawlSpider):
 
    def __init__(self, allowed_domains=[], start_urls=[],
            rules=[], findtag='', finditemprop='', keywords='', **kwargs):
        CrawlSpider.__init__(self, **kwargs)
        self.allowed_domains = allowed_domains
        self.start_urls = start_urls
        self.rules = rules
        self.findtag = findtag
        self.finditemprop = finditemprop
        self.keywords = keywords
 
    def parse_item(self, response):
        contentTags = []
 
        soup = BeautifulSoup(response.body)
 
        contentTags = soup.findAll(self.findtag, itemprop=self.finditemprop)
 
        for contentTag in contentTags:
            matchedResult = re.search(self.keywords, contentTag.text)
            if matchedResult:
                print('URL Found: ' + response.url)