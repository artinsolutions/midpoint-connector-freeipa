/**
 * Copyright (c) ARTIN solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.artin.idm.connector.freeipa;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;
import org.json.JSONArray;
import org.json.JSONObject;

import com.evolveum.polygon.rest.AbstractRestConnector;

/**
 * @author gpalos
 *
 */
@ConnectorClass(displayNameKey = "freeipa.connector.display", configurationClass = FreeIpaConfiguration.class)
public class FreeIpaConnector extends AbstractRestConnector<FreeIpaConfiguration> implements TestOp, SchemaOp, CreateOp, UpdateOp, DeleteOp, SearchOp<FreeIpaFilter>  {

	private static final Log LOG = Log.getLog(FreeIpaConnector.class);
	
	private static final String API_VERSION = "2.117";
	
	public static final String OBJECT_CLASS_USER = "user";
	public static final String OBJECT_CLASS_GROUP = "group";
	public static final String OBJECT_CLASS_ROLE = "role";
	
	private static final String[] CLASS_NAMES = {OBJECT_CLASS_USER, OBJECT_CLASS_GROUP, OBJECT_CLASS_ROLE};

	public static final String ATTR_CN = "cn";
	public static final String ATTR_UID = "uid";
	public static final String ATTR_DN = "dn";
	public static final String ATTR_GIVENNAME = "givenname";
	public static final String ATTR_SN = "sn";
	public static final String ATTR_USERPASSWORD = "userpassword";
	public static final String ATTR_RENAME = "rename";
	public static final String ATTR_NSACCOUNTLOCK = "nsaccountlock";
	public static final String ATTR_MEMBEROF_GROUP = "memberof_group";
	public static final String ATTR_MEMBEROF_ROLE = "memberof_role";
	public static final String ATTR_DESCRIPTION = "description";
	public static final String ATTR_KRBPASSWORDEXPIRATION = "krbpasswordexpiration";
	
	public static final String ATTR_IPAUNIQUEID = "ipauniqueid";
	public static final String ATTR_MEPMANAGEDENTRY = "mepmanagedentry";
	public static final String ATTR_OBJECTCLASS = "objectclass";
	public static final String ATTR_KRBLOGINFAILEDCOUNT = "krbloginfailedcount";
	public static final String ATTR_KRBEXTRADATA = "krbextradata";
	public static final String ATTR_KRBLASTPWDCHANGE = "krblastpwdchange";
	public static final String ATTR_KRBLASTFAILEDAUTH = "krblastfailedauth";
	public static final String ATTR_IPANTSECURITYIDENTIFIER = "ipantsecurityidentifier";
	public static final String ATTR_KRBTICKETFLAGS = "krbticketflags";
	
	public static final String ATTR_IPANTHASH = "ipanthash"; // freeradius
	
	
	public static final String ATTR_NOPRIVATE = "noprivate";
	public static final String ATTR_GIDNUMBER = "gidnumber";
	
	
	// alternative config because MID-5883
	private static final boolean DISABLE_ADMINISTRATIVE_STATUS = true; // workaround
	
	
	
	private static final List<String> USER_MULTIVALUED = Arrays.asList("krbprincipalname", "mail", "telephonenumber", "mobile", "pager", "facsimiletelephonenumber",
			"carlicense", "ipasshpubkey", "ipauserauthtype", "userclass", "departmentnumber", "usercertificate", /*"noprivate", */"no_members");
	
	
	// Free IPA schema cache
	private static JSONObject schema = null;
	
    @Override
    public void init(Configuration configuration) {
        LOG.info("Initializing {0} connector instance {1}", this.getClass().getSimpleName(), this);
    	super.init(configuration);
        
    	// log in as post over HTTPS, Password Authentication see: https://vda.li/en/posts/2015/05/28/talking-to-freeipa-api-with-sessions/
    	CloseableHttpClient client = getHttpClient();
    	
    	final List<String> passwordList = new ArrayList<String>(1);
        GuardedString guardedPassword = getConfiguration().getPassword();
        if (guardedPassword != null) {
            guardedPassword.access(new GuardedString.Accessor() {
                @Override
                public void access(char[] chars) {
                    passwordList.add(new String(chars));
                }
            });
        }
        String password = null;
        if (!passwordList.isEmpty()) {
            password = passwordList.get(0);
        }  
        
        // log in
        HttpPost httpPost = new HttpPost(getConfiguration().getServiceAddress()+"/session/login_password");
     
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("user", getConfiguration().getUsername()));
        params.add(new BasicNameValuePair("password", password));
        CloseableHttpResponse response;
        try {
			httpPost.setEntity(new UrlEncodedFormEntity(params));
			response = client.execute(httpPost);
	        System.out.println("Response is: "+response);        
			LOG.info("Connector instance created, authnetication result is {0}", response);
		} catch (UnsupportedEncodingException e) {
			LOG.error("cannot log in to freeIPA: " + e, e);
			throw new ConnectorIOException(e.getMessage(), e);
		} catch (IOException e) {
			LOG.error("cannot log in to freeIPA: " + e, e);
			throw new ConnectorIOException(e.getMessage(), e);
		}
    }
		
    @Override
    public void dispose() {
        super.dispose();
        schema = null;
    }    

//    @Override
//    public void checkAlive() {
//        test();
//        // TODO quicker test?
//    }
    
	@Override
	public void test() {
		// test connection
		JSONObject resp = callRequest(getIpaRequest("ping"));
		LOG.info("Free IPA environment details: \n{0}", resp);

        //client.close();   
	}
	

	@Override
	public Schema schema() {
		SchemaBuilder schemaBuilder = new SchemaBuilder(FreeIpaConnector.class);
		
		if (schema==null) {
			schema = callRequest(getIpaRequest("schema"));
		}
		
		for (String className : CLASS_NAMES) {
	        buildObjectClass(schemaBuilder, className);
		}

        return schemaBuilder.build();
	}
	
		

	private void buildObjectClass(SchemaBuilder schemaBuilder, String className) {
		ObjectClassInfoBuilder objClassBuilder = new ObjectClassInfoBuilder();
		objClassBuilder.setType(className);

        // UID & NAME are defaults
		JSONArray classes = FreeIpaConnector.schema.getJSONObject("result").getJSONObject("result").getJSONArray("classes");
		for (int i = 0; i < classes.length(); ++i) {
		    JSONObject jsonClass = classes.getJSONObject(i);
		    String jsonClassName = jsonClass.getString("name");
		    if (jsonClassName.equals(className)) {
		    	JSONArray jsonParams = jsonClass.getJSONArray("params");
		    	for (int p = 0; p < jsonParams.length(); ++p) {
		    		JSONObject jsonParam = jsonParams.getJSONObject(p);

		    		Boolean required = jsonParam.has("required") ? jsonParam.getBoolean("required") : true; //default is true
		    		String type = jsonParam.getString("type"); // Principal, datetime, Certificate,  ... str, bool, int
		    		
		    		Boolean multivalue = jsonParam.has("multivalue") ? jsonParam.getBoolean("multivalue") : false; //default is false
		    		String attributeName = jsonParam.getString("name");
		    		AttributeInfoBuilder attrBuilder = new AttributeInfoBuilder(attributeName);
		    		if ("bool".equals(type))
		    			attrBuilder.setType(Boolean.class);
	//		    		else if ("int".equals(type)) // uidnumber, gidnumber problem
	//		    			attrBuilder.setType(Integer.class);
		    		
		    		if (required)
		    			attrBuilder.setRequired(true);
		    		if (multivalue || ATTR_MEMBEROF_GROUP.equals(attributeName) || ATTR_MEMBEROF_ROLE.equals(attributeName)) // schema fix
		    			attrBuilder.setMultiValued(true); 

		            objClassBuilder.addAttributeInfo(attrBuilder.build());
		    	}
		    }
		}
		

		AttributeInfoBuilder attrObjectClassBuilder = new AttributeInfoBuilder(ATTR_OBJECTCLASS); // missing from schema (workaround)
		attrObjectClassBuilder.setMultiValued(true); 
        objClassBuilder.addAttributeInfo(attrObjectClassBuilder.build());		
		
		
		if (OBJECT_CLASS_USER.equals(className)) {
			if (!DISABLE_ADMINISTRATIVE_STATUS) {
				objClassBuilder.addAttributeInfo(OperationalAttributeInfos.ENABLE);     // status
			}
			
			AttributeInfoBuilder attrIpaUniqueIdBuilder = new AttributeInfoBuilder(ATTR_IPAUNIQUEID); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrIpaUniqueIdBuilder.build());
	        
			AttributeInfoBuilder attrMepManagedEntryBuilder = new AttributeInfoBuilder(ATTR_MEPMANAGEDENTRY); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrMepManagedEntryBuilder.build());

			AttributeInfoBuilder attrKrbLoginFailedCountBuilder = new AttributeInfoBuilder(ATTR_KRBLOGINFAILEDCOUNT); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrKrbLoginFailedCountBuilder.build());
	        
			AttributeInfoBuilder attrKrbExtraDataBuilder = new AttributeInfoBuilder(ATTR_KRBEXTRADATA); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrKrbExtraDataBuilder.build());

			AttributeInfoBuilder attrKrbLastPwdChangeBuilder = new AttributeInfoBuilder(ATTR_KRBLASTPWDCHANGE); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrKrbLastPwdChangeBuilder.build());

			AttributeInfoBuilder attrKrbLastFailedAuthBuilder = new AttributeInfoBuilder(ATTR_KRBLASTFAILEDAUTH); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrKrbLastFailedAuthBuilder.build());

			AttributeInfoBuilder attrDnBuilder = new AttributeInfoBuilder(ATTR_DN); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrDnBuilder.build());

			AttributeInfoBuilder attrIpaNtSecurityIdentifierBuilder = new AttributeInfoBuilder(ATTR_IPANTSECURITYIDENTIFIER); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrIpaNtSecurityIdentifierBuilder.build());

			AttributeInfoBuilder attrKrbTicketFlagsBuilder = new AttributeInfoBuilder(ATTR_KRBTICKETFLAGS); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrKrbTicketFlagsBuilder.build());

	        AttributeInfoBuilder attrNoPrivateBuilder = new AttributeInfoBuilder(ATTR_NOPRIVATE); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrNoPrivateBuilder.build());

			AttributeInfoBuilder attrIpaNtHashBuilder = new AttributeInfoBuilder(ATTR_IPANTHASH); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrIpaNtHashBuilder.build());
		}
		
		if (OBJECT_CLASS_GROUP.equals(className)) {
			AttributeInfoBuilder attrIpaUniqueIdBuilder = new AttributeInfoBuilder(ATTR_IPAUNIQUEID); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrIpaUniqueIdBuilder.build());

			AttributeInfoBuilder attrIpaNtSecurityIdentifierAuthBuilder = new AttributeInfoBuilder(ATTR_IPANTSECURITYIDENTIFIER); // missing from schema (workaround)
	        objClassBuilder.addAttributeInfo(attrIpaNtSecurityIdentifierAuthBuilder.build());
		}
		
        schemaBuilder.defineObjectClass(objClassBuilder.build());
	}


	private JSONObject getIpaRequest(String method) {
		return getIpaRequest(method, new JSONObject(), new JSONArray());
	}

	private JSONObject getIpaRequest(String method, JSONArray params_array) {
		return getIpaRequest(method, new JSONObject(), params_array);
	}
	
	private JSONObject getIpaRequest(String method, JSONObject params_value, JSONArray params_array) {
		JSONObject jo = new JSONObject();
        jo.put("method", method);

        params_value.put("version", API_VERSION);
        JSONArray params = new JSONArray();
        params.put(params_array);
        params.put(params_value);
        jo.put("params", params);

        jo.put("id", "0"); //TODO: request ID generation?

        LOG.info("json request: \n{0}", jo.toString());
        
        return jo;
	}

    protected JSONObject callRequest(JSONObject jo) {
    	HttpPost request = new HttpPost(getConfiguration().getServiceAddress()+"/session/json"); 
        // FIXME: don't log request here - password field !!!
//        LOG.info("request JSON: \n{0}", jo); //TODO: OK later,..
        request.setHeader("Referer", getConfiguration().getServiceAddress());
        request.setHeader("Content-Type", ContentType.APPLICATION_JSON.getMimeType());
        request.setHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());

        //authHeader(request);

        StringEntity entity = new StringEntity( jo.toString(), ContentType.APPLICATION_JSON);
        request.setEntity(entity);
        CloseableHttpResponse response = execute(request);
        LOG.ok("response: \n{0}", response);

        String result;
		try {
			result = processFreeIpaResponseErrors(response);
		} catch (ParseException e) {
			throw new ConnectorIOException("Error parsing response from FreeIPA: "+response, e);
		} catch (IOException e) {
			throw new ConnectorIOException("Error call request from FreeIPA: "+request+", json: "+jo, e);
		}
        LOG.ok("response body: \n{0}", result);
        closeResponse(response);
        
        return new JSONObject(result);
    }	
    
    private String processFreeIpaResponseErrors(CloseableHttpResponse response) throws ParseException, IOException{
    	// status is 200 in every time :(
//      super.processResponseErrors(response);

    	String result = EntityUtils.toString(response.getEntity());
        LOG.ok("Result body: {0}", result);
        JSONObject jo = new JSONObject(result);
        
        if (jo.isNull("error")) {
        	// no error :)
        } else {
            JSONObject error = jo.getJSONObject("error");
            
            String error_name = error.getString("name");
        	String error_message = error.getString("message");
        	
        	// other specific codes...
        	
        	if ("DuplicateEntry".equals(error_name)) {
                closeResponse(response);
                throw new AlreadyExistsException(error_message);
        	}
        	else if ("NotFound".equals(error_name)) {
                closeResponse(response);
                throw new UnknownUidException(error_message);
        	}
        	else if ("EmptyModlist".equals(error_name) || "AlreadyActive".equals(error_name) || "AlreadyInactive".equals(error_name)) {
        		LOG.warn("Ignoring request error message: {0}", result);
        	} else {
            	// general error
                closeResponse(response);
                throw new ConnectorIOException("Error: " + error + " when parsing result: " + result);
        	}
        }
        return result;
    }

	@Override
	public FilterTranslator<FreeIpaFilter> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
		 return new FreeIpaFilterTranslator();
	}

	@Override
	public void executeQuery(ObjectClass objectClass, FreeIpaFilter query, ResultsHandler handler,
			OperationOptions options) 
	{
		try {
            LOG.info("executeQuery on {0}, query: {1}, options: {2}", objectClass, query, options);
            if (objectClass.is(OBJECT_CLASS_USER)) {
                //find by Login name (uid)
                if (query != null && query.byUid != null) {
                	JSONArray params = new JSONArray();
                	params.put(query.byUid);
                	JSONObject user = callRequest(getIpaRequest("user_show", new JSONObject().put("all", true), params));
//                	JSONObject status = callRequest(getIpaRequest("user_status", params));
                    ConnectorObject connectorObject = convertUserToConnectorObject(user.getJSONObject("result").getJSONObject("result"));
                    handler.handle(connectorObject);
                } else {
                	JSONObject users = callRequest(getIpaRequest("user_find", new JSONObject().put("all", true), new JSONArray()));
                	JSONArray results = users.getJSONObject("result").getJSONArray("result");
            		for (int i = 0; i < results.length(); ++i) {
            		    JSONObject user = results.getJSONObject(i);
                        ConnectorObject connectorObject = convertUserToConnectorObject(user);
                        handler.handle(connectorObject);
            		}
                	// TODO: paging if required later...
                }
            }
            else if (objectClass.is(OBJECT_CLASS_ROLE)) {
                //find by role name (uid)
                if (query != null && query.byUid != null) {
                	JSONArray params = new JSONArray();
                	params.put(query.byUid);
                	JSONObject role = callRequest(getIpaRequest("role_show", new JSONObject().put("all", true), params));
                    ConnectorObject connectorObject = convertRoleToConnectorObject(role.getJSONObject("result").getJSONObject("result"));
                    handler.handle(connectorObject);
                } else {
                	JSONObject roles = callRequest(getIpaRequest("role_find", new JSONObject().put("all", true), new JSONArray()));
                	JSONArray results = roles.getJSONObject("result").getJSONArray("result");
            		for (int i = 0; i < results.length(); ++i) {
            		    JSONObject role = results.getJSONObject(i);
                        ConnectorObject connectorObject = convertRoleToConnectorObject(role);
                        handler.handle(connectorObject);
            		}
                	// TODO: paging if required later...
                }
            }
            else if (objectClass.is(OBJECT_CLASS_GROUP)) {
                //find by group name (uid)
                if (query != null && query.byUid != null) {
                	JSONArray params = new JSONArray();
                	params.put(query.byUid);
                	JSONObject group = callRequest(getIpaRequest("group_show", new JSONObject().put("all", true), params));
                    ConnectorObject connectorObject = convertGroupToConnectorObject(group.getJSONObject("result").getJSONObject("result"));
                    handler.handle(connectorObject);
                } else {
                	JSONObject groups = callRequest(getIpaRequest("group_find", new JSONObject().put("all", true), new JSONArray()));
                	JSONArray results = groups.getJSONObject("result").getJSONArray("result");
            		for (int i = 0; i < results.length(); ++i) {
            		    JSONObject group = results.getJSONObject(i);
                        ConnectorObject connectorObject = convertGroupToConnectorObject(group);
                        handler.handle(connectorObject);
            		}
                	// TODO: paging if required later...
                }
            }
            else {
                // not found
                throw new UnsupportedOperationException("Unsupported object class " + objectClass);
            }
        } catch (IOException e) {
            throw new ConnectorIOException(e.getMessage(), e);
        }
	}

	private ConnectorObject convertUserToConnectorObject(JSONObject user) throws IOException {
		LOG.ok("JSON User as input: \n{0}", user);
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        ObjectClass objectClass = new ObjectClass(OBJECT_CLASS_USER);
        builder.setObjectClass(objectClass);        
        String uid = getMultiAsSingleValue(user, ATTR_UID);
        builder.setUid(new Uid(uid));
        builder.setName(new Name(uid));
        
        Iterator<String> keys = user.keys();

        while(keys.hasNext()) {
            String key = keys.next();
        	Object value = user.get(key); 
//    		LOG.ok("JSON key:{0}={1}", key, value);
            if (value instanceof JSONObject || value instanceof Boolean || value instanceof String) {
            	// single value
            	addAttr(builder, key, value);
            } else if (value instanceof JSONArray) {
            	// multi value
            	JSONArray values = user.getJSONArray(key);
            	
            	List<String> valueList = new ArrayList<String>();
            	for(int i = 0; i < values.length(); i++){
            		Object val = values.get(i);
            		
            		if (val instanceof JSONObject) {
                		// handling "__datetime__", "__base64__"...
                		// "krbextradata": [{"__base64__": "AAJeR8pdcm9vdC9hZG1pbkBMQUIuQVJUSU4uSU8A"}]
                		// "krbpasswordexpiration": [{"__datetime__": "20191112054710Z"}]
                		// "krblastpwdchange": [{"__datetime__": "20191112054710Z"}]
            			JSONObject joVal = ((JSONObject)val);
            			Iterator<String> keysForVal = joVal.keys();
            			while(keysForVal.hasNext()) {
            			    String keyForVal = keysForVal.next();
            			    valueList.add(joVal.getString(keyForVal));
            			}
            		}
            		else {
            			valueList.add(values.getString(i));
            		}
            	}            	
            	String[] valueArray = valueList.toArray(new String[0]);
                builder.addAttribute(key, valueArray);
            }	
        }       
        
        if (user.has(ATTR_NSACCOUNTLOCK) && !DISABLE_ADMINISTRATIVE_STATUS) {
            boolean enabled = !user.getBoolean(ATTR_NSACCOUNTLOCK);
            addAttr(builder, OperationalAttributes.ENABLE_NAME, enabled);
        }

        ConnectorObject connectorObject = builder.build();
        LOG.ok("convertUserToConnectorObject, user: {0}, \n\tconnectorObject: {1}",
        		uid, connectorObject);
        return connectorObject;
	}

	
	
	private ConnectorObject convertRoleToConnectorObject(JSONObject role) throws IOException {
		LOG.ok("JSON Role as input: \n{0}", role);
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        ObjectClass objectClass = new ObjectClass(OBJECT_CLASS_ROLE);
        builder.setObjectClass(objectClass);        
        String uid = getMultiAsSingleValue(role, ATTR_CN);
        builder.setUid(new Uid(uid));
        builder.setName(new Name(uid));
        
        Iterator<String> keys = role.keys();

        while(keys.hasNext()) {
            String key = keys.next();
            
        	Object value = role.get(key); 
            if (value instanceof JSONObject) {
            	// single value
            	addAttr(builder, key, value);
            } else if (value instanceof JSONArray) {
            	// multi value
            	JSONArray values = role.getJSONArray(key);
            	
            	List<String> valueList = new ArrayList<String>();
            	for(int i = 0; i < values.length(); i++){
            		valueList.add(values.getString(i));
            	}            	
            	String[] valueArray = valueList.toArray(new String[0]);
                builder.addAttribute(key, valueArray);
            }	
        }       
     
        ConnectorObject connectorObject = builder.build();
        LOG.ok("convertRoleToConnectorObject, user: {0}, \n\tconnectorObject: {1}",
        		uid, connectorObject);
        return connectorObject;
	}
	
	private ConnectorObject convertGroupToConnectorObject(JSONObject group) throws IOException {
		LOG.ok("JSON Group as input: \n{0}", group);
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        ObjectClass objectClass = new ObjectClass(OBJECT_CLASS_GROUP);
        builder.setObjectClass(objectClass);        
        String uid = getMultiAsSingleValue(group, ATTR_CN);
        builder.setUid(new Uid(uid));
        builder.setName(new Name(uid));
        
        Iterator<String> keys = group.keys();

        while(keys.hasNext()) {
            String key = keys.next();
            
        	Object value = group.get(key); 
            if (value instanceof JSONObject) {
            	// single value
            	addAttr(builder, key, value);
            } else if (value instanceof JSONArray) {
            	// multi value
            	JSONArray values = group.getJSONArray(key);
            	
            	List<String> valueList = new ArrayList<String>();
            	for(int i = 0; i < values.length(); i++){
            		valueList.add(values.getString(i));
            	}            	
            	String[] valueArray = valueList.toArray(new String[0]);
                builder.addAttribute(key, valueArray);
            }	
        }       
     
        ConnectorObject connectorObject = builder.build();
        LOG.ok("convertGroupToConnectorObject, group: {0}, \n\tconnectorObject: {1}",
        		uid, connectorObject);
        return connectorObject;
	}
		
	private String getMultiAsSingleValue(JSONObject user, String attrName) {
		if (!user.has(attrName))
			return null;
		
		Object val = user.get(attrName);
		if (val instanceof JSONObject) {
			return user.getString(attrName);
		}
		else {
        	JSONArray values = user.getJSONArray(attrName);
            if (values.length()==1)
            	return (String) values.get(0);
            else
            	throw new ConnectorException("For attribute: "+attrName+" we have several values: "+values + " for user: "+user);
		}
	}

	@Override
	public Uid create(ObjectClass objectClass, Set<Attribute> attributes, OperationOptions options) {
		if (objectClass.is(OBJECT_CLASS_USER)) {
            return createOrUpdateUser(null, attributes);
		} else if (objectClass.is(OBJECT_CLASS_ROLE)) {    
            return createOrUpdateRole(null, attributes);
		} else if (objectClass.is(OBJECT_CLASS_GROUP)) {    
            return createOrUpdateGroup(null, attributes);
        } else { 
            // not found
            throw new UnsupportedOperationException("Unsupported object class " + objectClass);
        }
	}
	
	@Override
	public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> attributes, OperationOptions options) {
		if (objectClass.is(OBJECT_CLASS_USER)) {
            return createOrUpdateUser(uid, attributes);
		} else if (objectClass.is(OBJECT_CLASS_ROLE)) {    
            return createOrUpdateRole(uid, attributes);
		} else if (objectClass.is(OBJECT_CLASS_GROUP)) {    
            return createOrUpdateGroup(uid, attributes);
        } else { 
            // not found
            throw new UnsupportedOperationException("Unsupported object class " + objectClass);
        }	
	}

	private Uid createOrUpdateUser(Uid uid, Set<Attribute> attributes) {
        LOG.ok("createOrUpdateUser, Uid: {0}, attributes: {1}", uid, attributes);
        if (attributes == null || attributes.isEmpty()) {
            LOG.ok("request ignored, empty attributes");
            return uid;
        }
        boolean create = uid == null;
        JSONObject params = new JSONObject();
        String loginNew = getStringAttr(attributes, Name.NAME); //old or new login to rename
        if (StringUtil.isBlank(loginNew)) {
        	loginNew = uid.getUidValue();
        }
        
        if (create && StringUtil.isBlank(loginNew)) {
            throw new InvalidAttributeValueException("Missing mandatory attribute " + Name.NAME);
        }
        if (create && StringUtil.isBlank(getStringAttr(attributes, ATTR_GIVENNAME))) {
            throw new InvalidAttributeValueException("Missing mandatory attribute " + ATTR_GIVENNAME);
        }
        if (create && StringUtil.isBlank(getStringAttr(attributes, ATTR_SN))) {
            throw new InvalidAttributeValueException("Missing mandatory attribute " + ATTR_SN);
        }
        if (create && StringUtil.isBlank(getStringAttr(attributes, ATTR_CN))) {
            throw new InvalidAttributeValueException("Missing mandatory attribute " + ATTR_CN);
        }

        final List<String> passwordList = new ArrayList<String>(1);
        GuardedString guardedPassword = getAttr(attributes, OperationalAttributeInfos.PASSWORD.getName(), GuardedString.class);
        if (guardedPassword != null) {
            guardedPassword.access(new GuardedString.Accessor() {
                @Override
                public void access(char[] chars) {
                    passwordList.add(new String(chars));
                }
            });
        }
        String password = null;
        if (!passwordList.isEmpty()) {
            password = passwordList.get(0);
        }
        // workaround for https://www.freeipa.org/page/New_Passwords_Expired
        String krbPasswordExpiration = null; 
        for (Attribute attr : attributes) {
        	String attrName = attr.getName();
        	List<Object> attrValue = attr.getValue();
        	if (attrName.equals(FreeIpaConnector.ATTR_KRBPASSWORDEXPIRATION) && attrValue!=null) {
        		krbPasswordExpiration = (String) attrValue.get(0); // need to set password expiration
        	}
        	if (attrName.equals(OperationalAttributeInfos.ENABLE.getName())  
        			|| attrName.equals(OperationalAttributeInfos.PASSWORD.getName()) 
        			|| attrName.equals(ATTR_UID)
        			|| attrName.equals(Name.NAME)
        			|| attrName.equals(FreeIpaConnector.ATTR_MEMBEROF_ROLE)
        			|| attrName.equals(FreeIpaConnector.ATTR_MEMBEROF_GROUP)) {
        		continue; // proceeed in different way...
        	}
        	

        	
    		if (USER_MULTIVALUED.contains(attrName)) {
    			JSONArray values = new JSONArray();
    			if (attrValue!=null) {
            		for (Object av: attrValue)
            			values.put(av);
    			}
        		params.put(attrName, values);
    		}
    		else {
    			if (attrValue==null) {
    				params.put(attrName, JSONObject.NULL);
    			}
    			else {
    				params.put(attrName, attrValue.get(0));
    			}
    		}
        }
        
        if (!create && !uid.getUidValue().equals(loginNew)) {
        	params.put(ATTR_RENAME, loginNew); // rename user, https://www.redhat.com/archives/freeipa-users/2014-March/msg00072.html
        }
        
        JSONArray params_array = new JSONArray();
        params_array.put(create ? loginNew : uid.getUidValue());
		JSONObject request = getIpaRequest(create ? "user_add" : "user_mod", params, params_array);
        
        LOG.ok("user request (without password): {0}", request.toString());

        if (password != null) {
            params.put(ATTR_USERPASSWORD, password);
        }

        if (params.length()>0) {
	        JSONObject jores = callRequest(request);
	        LOG.info("response UID: {0}, body: {1}", loginNew, jores);
        }
        
        handleEnable(attributes, loginNew, create);
        handleRoles(attributes, loginNew, create);
        handleGroups(attributes, loginNew, create);
        
        if (krbPasswordExpiration != null) {
        	// set again password expiration
        	JSONObject paramsExp = new JSONObject();
            paramsExp.put(ATTR_KRBPASSWORDEXPIRATION, krbPasswordExpiration);

            JSONArray params_arrayExp = new JSONArray();
            params_arrayExp.put(create ? loginNew : uid.getUidValue());
            
        	JSONObject requestExp = getIpaRequest("user_mod", paramsExp, params_arrayExp);
	        JSONObject jores = callRequest(requestExp);
	        LOG.info("response after set krbpasswordexpiration UID: {0}, body: {1}", loginNew, jores);
        }
        
        return new Uid(loginNew);
    }    
	
	private Uid createOrUpdateRole(Uid uid, Set<Attribute> attributes) {
        LOG.ok("createOrUpdateRole, Uid: {0}, attributes: {1}", uid, attributes);
        if (attributes == null || attributes.isEmpty()) {
            LOG.ok("request ignored, empty attributes");
            return uid;
        }
        boolean create = uid == null;
        JSONObject params = new JSONObject();
        String roleNameNew = getStringAttr(attributes, Name.NAME); //old or new login to rename
        if (StringUtil.isBlank(roleNameNew)) {
        	roleNameNew = uid.getUidValue();
        }
        
        if (create && StringUtil.isBlank(roleNameNew)) {
            throw new InvalidAttributeValueException("Missing mandatory attribute " + Name.NAME);
        }
        
        putFieldValueIfExists(attributes, ATTR_DESCRIPTION, params);
                

        if (!create && !uid.getUidValue().equals(roleNameNew)) {
        	params.put(ATTR_RENAME, roleNameNew);
        }
        
        JSONArray params_array = new JSONArray();
        params_array.put(create ? roleNameNew : uid.getUidValue());
		JSONObject request = getIpaRequest(create ? "role_add" : "role_mod", params, params_array);
        
        LOG.ok("Role request {0}", request.toString());

        if (params.length()>0) {
	        JSONObject jores = callRequest(request);
	        LOG.info("response UID: {0}, body: {1}", roleNameNew, jores);
        }
        
        return new Uid(roleNameNew);
    }    	
	
	private Uid createOrUpdateGroup(Uid uid, Set<Attribute> attributes) {
        LOG.ok("createOrUpdateGroup, Uid: {0}, attributes: {1}", uid, attributes);
        if (attributes == null || attributes.isEmpty()) {
            LOG.ok("request ignored, empty attributes");
            return uid;
        }
        boolean create = uid == null;
        JSONObject params = new JSONObject();
        String groupNameNew = getStringAttr(attributes, Name.NAME); //old or new login to rename
        if (StringUtil.isBlank(groupNameNew)) {
        	groupNameNew = uid.getUidValue();
        }
        
        if (create && StringUtil.isBlank(groupNameNew)) {
            throw new InvalidAttributeValueException("Missing mandatory attribute " + Name.NAME);
        }
        
        for (Attribute attr : attributes) {
        	String attrName = attr.getName();
        	if (attrName.equals(ATTR_UID)
        			|| attrName.equals(Name.NAME)) {
        		continue; // proceeed in different way...
        	}
        	
        	List<Object> attrValue = attr.getValue();
        	
    		if (USER_MULTIVALUED.contains(attrName)) {
        		JSONArray values = new JSONArray();
        		for (Object av: attrValue)
        			values.put(av);
        		params.put(attrName, values);
    		}
    		else {
    			params.put(attrName, attrValue.get(0));
    		}
        }                
        
        if (!create && !uid.getUidValue().equals(groupNameNew)) {
        	params.put(ATTR_RENAME, groupNameNew); // rename user, https://www.redhat.com/archives/freeipa-users/2014-March/msg00072.html
        }
        
        JSONArray params_array = new JSONArray();
        params_array.put(create ? groupNameNew : uid.getUidValue());
		JSONObject request = getIpaRequest(create ? "group_add" : "group_mod", params, params_array);
        
        LOG.ok("Group request {0}", request.toString());

        if (params.length()>0) {
	        JSONObject jores = callRequest(request);
	        LOG.info("response UID: {0}, body: {1}", groupNameNew, jores);
        }
        
        return new Uid(groupNameNew);
    }    		
	
	
    private void putFieldValueIfExists(Set<Attribute> attributes, String fieldName, JSONObject jo) {
        String value = getStringAttr(attributes, fieldName);
        if (value != null) {
            jo.put(fieldName, value);
        }
    }

	private void handleRoles(Set<Attribute> attributes, String login, boolean create) {
    	for (Attribute attr : attributes) {
    		if (ATTR_MEMBEROF_ROLE.equals(attr.getName())) {
    			List<Object> vals = attr.getValue();
				if (create) {
					// is enought to add new role assignments, not need to read user details
					for (Object val : vals) {
    		            addRemoveMember("role_add_member", login, (String) val);
					}
				}
				else {
                	JSONObject user = callRequest(getIpaRequest("user_show", new JSONArray().put(login))).getJSONObject("result").getJSONObject("result");
                	JSONArray currentRoles = new JSONArray();
                	if (user.has(ATTR_MEMBEROF_ROLE))
                		currentRoles = user.getJSONArray(ATTR_MEMBEROF_ROLE);
	    			if (vals==null || vals.isEmpty()) {
	    				//need to remove all current roles
	    				for (int i = 0; i < currentRoles.length(); i++) {
							addRemoveMember("role_remove_member", login, currentRoles.getString(i));
	    				}
	    			}
	    			if (vals != null) {
	        			// need to add new ones
	    				for (Object val : vals) {
							String role = (String) val;
							boolean needToAdd = true;
		    				for (int i = 0; i < currentRoles.length(); i++) {
								if (role.equals(currentRoles.getString(i))) {
									needToAdd = false;
								}
		    				}
							if (needToAdd) {
								addRemoveMember("role_add_member", login, role);
							}
						}
	    				// need to remove old ones
	    				for (int i = 0; i < currentRoles.length(); i++) {
	    					String currentRole = currentRoles.getString(i);
	    					boolean needToRemove = true;
	    					for (Object val : vals) {
								String role = (String) val;
								if (currentRole.equals(role)) {
									needToRemove = false;
								}
	    					}
							if (needToRemove) {
								addRemoveMember("role_remove_member", login, currentRole);
							}
	    				}
	    			}
				}
    		}
    	}
	}

    private void handleGroups(Set<Attribute> attributes, String login, boolean create) {
    	for (Attribute attr : attributes) {
    		if (ATTR_MEMBEROF_GROUP.equals(attr.getName())) {
    			List<Object> vals = attr.getValue();
				if (create) {
					// is enought to add new role assignments, not need to read user details
					for (Object val : vals) {
    		            addRemoveMember("group_add_member", login, (String) val);
					}
				}
				else {
                	JSONObject user = callRequest(getIpaRequest("user_show", new JSONArray().put(login))).getJSONObject("result").getJSONObject("result");
                	JSONArray currentGroups = new JSONArray();
                	if (user.has(ATTR_MEMBEROF_GROUP))
                		currentGroups = user.getJSONArray(ATTR_MEMBEROF_GROUP);
	    			if (vals==null || vals.isEmpty()) {
	    				//need to remove all current roles
	    				for (int i = 0; i < currentGroups.length(); i++) {
							addRemoveMember("group_remove_member", login, currentGroups.getString(i));
	    				}
	    			}
	    			if (vals != null) {
	        			// need to add new ones
	    				for (Object val : vals) {
							String group = (String) val;
							boolean needToAdd = true;
		    				for (int i = 0; i < currentGroups.length(); i++) {
								if (group.equals(currentGroups.getString(i))) {
									needToAdd = false;
								}
		    				}
							if (needToAdd) {
								addRemoveMember("group_add_member", login, group);
							}
						}
	    				// need to remove old ones
	    				for (int i = 0; i < currentGroups.length(); i++) {
	    					String currentGroup = currentGroups.getString(i);
	    					boolean needToRemove = true;
	    					for (Object val : vals) {
								String group = (String) val;
								if (currentGroup.equals(group)) {
									needToRemove = false;
								}
	    					}
							if (needToRemove) {
								addRemoveMember("group_remove_member", login, currentGroup);
							}
	    				}
	    			}
				}
    		}
    	}
	}    
	private void addRemoveMember(String command, String login, String roleOrGroupName) {
        LOG.ok("run command {0} on user {1} and {2}", command, login, roleOrGroupName);

        JSONObject params_value = new JSONObject().put("user", login);

		JSONArray params_array = new JSONArray();
        params_array.put(roleOrGroupName);
        
		JSONObject request = getIpaRequest(command, params_value, params_array);
		JSONObject jores = callRequest(request);
		
        LOG.info("response body: {0}", jores, login);
	}

	private void handleEnable(Set<Attribute> attributes, String login, boolean create) {
        Boolean enable = getAttr(attributes, OperationalAttributes.ENABLE_NAME, Boolean.class);

        if (enable != null && !(create && enable)) {
        	String command = enable ? "user_enable": "user_disable";
            JSONArray params_array = new JSONArray();
            params_array.put(login);
        	
    		JSONObject request = getIpaRequest(command, new JSONObject(), params_array);
    		JSONObject jores = callRequest(request);
            LOG.info("response body: {0} for command: {1}", jores, command);
        }
    }

	@Override
	public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
		if (objectClass.is(OBJECT_CLASS_USER)) {
			// TODO also preserve=true & user_undel?
            LOG.ok("delete user, Uid: {0}", uid);
            JSONArray params_array = new JSONArray();
            params_array.put(uid.getUidValue());
    		JSONObject request = getIpaRequest("user_del", new JSONObject(), params_array);
    		JSONObject jores = callRequest(request);
            LOG.info("response body: {0} for user deletion for uid: ", jores, uid);
		} else if (objectClass.is(OBJECT_CLASS_ROLE)) {
            LOG.ok("delete role, Uid: {0}", uid);
            JSONArray params_array = new JSONArray();
            params_array.put(uid.getUidValue());
    		JSONObject request = getIpaRequest("role_del", new JSONObject(), params_array);
    		JSONObject jores = callRequest(request);
            LOG.info("response body: {0} for role deletion for uid: ", jores, uid);
		} else if (objectClass.is(OBJECT_CLASS_GROUP)) {
            LOG.ok("delete group, Uid: {0}", uid);
            JSONArray params_array = new JSONArray();
            params_array.put(uid.getUidValue());
    		JSONObject request = getIpaRequest("group_del", new JSONObject(), params_array);
    		JSONObject jores = callRequest(request);
            LOG.info("response body: {0} for group deletion for uid: ", jores, uid);
        } else { 
            // not found
            throw new UnsupportedOperationException("Unsupported object class " + objectClass);
        }
	}	

}
