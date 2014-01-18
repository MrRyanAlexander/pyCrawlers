import urllib2

def get_page(s):
    sourceFile = urllib2.urlopen(s)
    print_all_links(sourceFile.read())

def get_next_target(page):
    start_link = page.find('<a href=')

    if start_link == -1:
        return None, 0
    
    start_quote = page.find('"', start_link)
    end_quote = page.find('"', start_quote + 1)
    url = page[start_quote + 1:end_quote]
    return url, end_quote

def print_all_links(page):
    while True:
        url, endpos = get_next_target(page)
        if url:
            print url
            page = page[endpos:]
        else:
            break

print get_page("http://www.cragslist.org/sss/")