import hashlib
import hmac

class BtyDriver:
	"""Documentacion BtyDriver"""
	
	def hex2bin(self, text):
		relation = {'0':0, '1':1, '2':2, '3':3, '4':4, '5':5, '6':6, '7':7, '8':8, '9':9, 'a':10, 'b':11, 'c':12, 'd':13, 'e':14, 'f':15}
		text = text.lower()
		binstr = ''
		for i in xrange(len(text)/2):
			binstr += chr(relation[text[i*2]]*16+relation[text[i*2+1]])
		return binstr
	
	def set_config (self, pub_key, priv_key, user_id = 0, api_version="v4", auth_mode="fs2k"):
		"""Documentacion set_config"""
		
		self.pub_key     = pub_key
		self.priv_key    = priv_key
		self.user_id     = user_id
		self.api_version = api_version
		self.auth_mode   = auth_mode
	
	def construct_url (self, controller, method, request_type, params):
		"""Documentacion construct_url"""
		
		post_plain_string = ''
		rc_uri = '/'+controller+'/'+method+'/'
		
		if request_type == 'GET':
			rc_uri += '/'.join(params)
		else:
			for key in params.keys():
				post_plain_string += '_'+key+'.'+params[key]+'_'
			
			post_plain_string = hashlib.sha1(post_plain_string).hexdigest()
		
		key = self.hex2bin(self.priv_key)
		
		url =	'http://www.bananity.com/api/v4'+rc_uri+
				'?api_version='+self.api_version+
				'&auth_mode='+self.auth_mode+
				'&consumer_public_key='+self.pub_key
		
		if self.user_id != 0:
			url += '&user_id='+self.user_id
		
		secure_hash = hmac.HMAC(key, rc_uri+post_plain_string, hashlib.sha1)
		
		$url += '&secure_hash='+secure_hash
		
		return url
