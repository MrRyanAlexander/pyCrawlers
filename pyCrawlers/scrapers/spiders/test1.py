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
            #matches_list = self.remove_duplicate_ads(posts, ads)
            #if matches_list:
            return ads
            #unicode_to_str(str(ads, encoding='ascii')

    #def get_media_requests(self, item, info):
    #    for image_url in item['image_urls']:
    #        yield Request(image_url)