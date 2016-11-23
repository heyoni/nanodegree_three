# nanodegree_three

#Installation
Install google appengine SDK for python at https://cloud.google.com/appengine/docs/python/download
Extract contents into folder and run ```dev_appserver.py .```
That will setup a webserver at localhost:8080, goto /blog to find the blog
#Overview

Users can write blog posts that are visible to anyone browsing this website. Included is the ability for others to post 
comments and save postings that they like; so long as they are registered. Website registration doesn't require any e-mail
address. Website was built using google app cloud

#Models
###accounts
The password field stores a salt separated by a pipe followed by a hash.


#Classes
##BaseHandler
Contains shared functions inherited by all other RequestHandlers for rendering templates, 
sending back plain-text, setting and reading cookie values as well as resetting them.
###Post
This one is used for displaying posts. The render function replaces traditional line breaks with HTML <BR> tags.
###BlogFront
Standard front page showing the 10 most recent blog posts
###PostPage
Used for deleting old posts.
###EditPost
Using GET will display a populated form for a specific post ID and using POST will alter that post.
###UpvotePost
This will add a post to a list of saved ones stored in db.Model.Upvote
###NewPost
Used for creating new posts or editing old ones.
###Signup
Gathers user entered information and accounts that to db.Model.accounts and sets the user's cookie
###Welcome
If the person has just logged in, it will display a welcome banner
###Login
Login function takes in user and pw then uses the stored salt in db.Model.accounts.password to compare to hash that's stored in that same field.
###Logout
Clears all cookies
###EditComments
Used for editing comments.