import scraperwiki
#html = scraperwiki.scrape("http://slo.craigslist.org/search/apa?zoomToPosting=&query=SLO&srchType=A&minAsk=&maxAsk=4000&bedrooms=3")
#print html

import lxml.etree
import lxml.html

# create an example case

html = """
"""

root = lxml.html.fromstring(html)  # an lxml.etree.Element object
listings = root.cssselect('p') # get all the <p> tags from craigslist html - they correspond to entries

for listing in listings:

    ###there will always be a description, and always a "date" and "price" tag
    title = listing.cssselect('#postingtitle')[0].text #is there always a description? is it always in the second "a" tag? - assuming this always exists
    descrip = listing.cssselect('#postingbody')[0].text#there is always a date associated with the tag
    location = listing.cssselect('ul.blurbs li')[0].text #find the <span class="price"> tag - assuming this tag always exists, even if no price is listed


    ###bedrooms and sqft are in span pnr tag, but are after the span price tag, so need to find all text in pnr tag and then analyze
    info = listing.cssselect('span.pnr')[0]
    content = info.text_content() #includes the text of bedroom # as well as the sqft (optional in a listing) - need to break up later using text analysis
    
    start = content.find('/')+2
    mid = content.find('br')#finds the br text
    end = content.find('ft')
    br = content[start:mid]#number of bedrooms

    if end != -1:#if it found sqft in the entry
        sqft = content[mid+5:end]#the sqft will always start 5 chars after the "br" text marker
    else:
        sqft = "sqft not listed"


    ###for attributes that may not be listed in entry, need to verify existence before extracting text
    small_tags = listing.cssselect('small')
    if len(small_tags) == 2:
        location = small_tags[1].text
        location = location[2:-1]#cut off the parenthesis
    else:
        location = "location not listed"

    if len(price) > 0:
        rent = price[0].text
    else:
        rent = "no rent listed" #if there is no listed rent
    
    try:#latitude and longitude are not always listed
        latitude = listing.attrib['data-latitude']
    except KeyError: #if data-latitude isn't an attribue of the p tag / entry
        latitude = 'latitude not listed'
    try:
        longitude = listing.attrib['data-longitude']
    except KeyError:
        longitude = 'latitude not listed'


    ###create data entry and record it in sqlite database
    data = {
        'description' : descrip,
        'date' : date,
        'rent' : rent, 
        'bedrooms' : br,
        'squarefootage' : sqft,
        'location' : location,
        'latitude' : latitude,
        'longitude' : longitude }
       
    scraperwiki.sqlite.save(unique_keys=['description'], data = data) # save the records one by one

    print scraperwiki.sqlite.select("* from swdata limit 10")[0]
