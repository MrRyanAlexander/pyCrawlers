# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/topics/items.html

from scrapy.item import Item, Field

class CraigslistSampleItem(Item):
    # define the fields for your item here like:
    # name = Field()
    url = Field()
    title = Field()
    description = Field()
    image_urls = Field()
    images = Field()

    pass
