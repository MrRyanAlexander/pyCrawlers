 # test spider
#
# See documentation in:
# http://mherman.org/blog/2012/11/05/scraping-web-pages-with-scrapy/

from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.contrib.linkextractors.sgml import SgmlLinkExtractor
from scrapy.selector import HtmlXPathSelector
from scrapy.contrib.pipeline.images import ImagesPipeline
from scrapy.http import Request
from craigslist_sample.items import CraigslistSampleItem
#from scrapy.utils.python import unicode_to_str


class MySpider(CrawlSpider):
    name = "craig1"
    allowed_domains = ['craigslist.org']
    start_urls = ['http://stlouis.craigslist.org/ppa/']
    #rules = [Rule(SgmlLinkExtractor(allow=['/ppd/\d+\.html']), 'parse_ads')]
    rules = (
        Rule(SgmlLinkExtractor(allow=(r'index\100\.html')), follow=True),
        Rule(SgmlLinkExtractor(allow=(r'/ppd/\d+\.html')), callback='parse_ads', follow=True),
    )

    def parse_ads(self, response):
        hxs = HtmlXPathSelector(response)
        posts = hxs.select('//article[@id="pagecontainer"]/section[@class="body"]')
        #unicode_to_str(str(posts), encoding="ascii")
        ads = []

        for post in posts:
            ad = CraigslistSampleItem()
            ad['url'] = response.url
            ad['title'] = post.select('//h2[@class="postingtitle"]/text()').extract()
            ad['description'] = post.select('//section[@id="postingbody"]/text()').extract()
            ad['image_urls'] = post.select("//img/@src").extract()
            ads.append(ad)   

            """
           |-------------+++---------|
                div.postinginfos 
           |--------------+----------|
              p.postinginfo = id[0]
           |--------------+----------|
            p.postinginfo = posted[1]
           |--------------+----------|
            p.postinginfo = updated[2]
           |-------------+++---------|

            """
            try:
                posted = listing.attrib['p.postinginfo'][1]
            except KeyError; #this should always return a value
                posted = 'Error, no post logged'
            try:
                updated = listing.attrib['p.postinginfo'][2]
            except KeyError; #only returns when ad has not been reposted
                updated = '1st POST'

                try:
                #posted = listing.attrib['p.postinginfo'][1]
                loader.add_xpath('posted', '//p[@class="postinginfo"]'[1])
            except KeyError; #this should always return a value
                loader.add_xpath('Error, no post logged')

            try:
                #updated = listing.attrib['p.postinginfo'][2]
                loader.add_xpath('updated', '//p[@class="postinginfo"]'[2])

            except KeyError; #only returns when ad has not been reposted
                loader.add_xpath('1st POST')

                ###create data entry and record it in sqlite database
            data = {
                'title' : title,
                'description' : descrip,
                'url' : url, 
                'image_urls' : image_urls,
                'location' : location,
                'posted' : posted,
                'updated' : updated }
       
            scraperwiki.sqlite.save(unique_keys=['title'], data = data)
            return ads
