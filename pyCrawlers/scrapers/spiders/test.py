# test spider
#
# See documentation in:
# http://mherman.org/blog/2012/11/05/scraping-web-pages-with-scrapy/

from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.contrib.linkextractors.sgml import SgmlLinkExtractor
from scrapy.selector import HtmlXPathSelector
from scrapy.http import Request
from scrapy.contrib.pipeline.images import ImagesPipeline
from craigslist_sample.items import CraigslistSampleItem

class MySpider(CrawlSpider):
    name = "craig"
    allowed_domains = ['craigslist.org']
    start_urls = ['http://stlouis.craigslist.org/ppa/']
    rules = [Rule(SgmlLinkExtractor(allow=['/ppd/\d+\.html']), 'parse_ads')]

    def parse_ads(self, response):
        hxs = HtmlXPathSelector(response)

        ad = CraigslistSampleItem()
        ad['url'] = response.url
        ad['title'] = hxs.select("//h2[@class='postingtitle']/text()").extract()
        ad['description'] = hxs.select("//section[@id='postingbody']/text()").extract()
        ad['images'] = hxs.select("//section[@id='postingbody']//img/@src").extract()
        return ad
