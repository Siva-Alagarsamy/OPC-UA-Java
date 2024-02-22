/* Copyright (c) 1996-2015, OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/
package org.opcfoundation.ua.transport.https;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.opcfoundation.ua.builtintypes.ServiceRequest;
import org.opcfoundation.ua.builtintypes.ServiceResponse;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.EndpointConfiguration;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.encoding.EncoderContext;
import org.opcfoundation.ua.encoding.binary.IEncodeableSerializer;
import org.opcfoundation.ua.transport.AsyncResult;
import org.opcfoundation.ua.transport.TransportChannelSettings;
import org.opcfoundation.ua.transport.UriUtil;
import org.opcfoundation.ua.transport.security.HttpsSecurityPolicy;
import org.opcfoundation.ua.transport.tcp.io.ITransportChannel;
import org.opcfoundation.ua.utils.CryptoUtil;
import org.opcfoundation.ua.utils.ObjectUtils;
import org.opcfoundation.ua.utils.StackUtils;
import org.opcfoundation.ua.utils.TimerUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.opcfoundation.ua.core.StatusCodes.Bad_Timeout;

/**
 * Https Opc-Ua Client connection to an endpoint.
 */
public class HttpsClient implements ITransportChannel {

	static final ServiceResultException BAD_TIMEOUT = new ServiceResultException( Bad_Timeout );
	static final Charset UTF8 = StandardCharsets.UTF_8;
	
	static final Logger logger = LoggerFactory.getLogger(HttpsClient.class);

	/** Request Id Counter */
	AtomicInteger requestIdCounter = new AtomicInteger( 0 /*StackUtils.RANDOM.nextInt()*/ );
	
	/** Transport channel settings */
	TransportChannelSettings transportChannelSettings;
	/** Connect Url */
	String connectUrl;
	/** Security policy */
	HttpsSecurityPolicy[] securityPolicies;
	
	/** Executor */
	Executor executor = StackUtils.getBlockingWorkExecutor();

	/** http-code scheme registry */
	Registry<ConnectionSocketFactory> sr;

	/** Client connection manager */
	PoolingHttpClientConnectionManager ccm;
	/** Max connections */
	int maxConnections = 20;
	/** HttpClient */
	CloseableHttpClient httpclient;
	
    /** Protocol */
    String protocol;
    
	/** Serializer */
	IEncodeableSerializer serializer;

	/** Security Policy */
	String securityPolicyUri;	
	
	/**
	 * List on pending requests. All reads and writes are done by synchronizing to the
	 * requests object. 
	 */
	Map<Integer, HttpsClientPendingRequest> requests = new ConcurrentHashMap<Integer, HttpsClientPendingRequest>();

	/**
	 * Timer that schedules future tasks 
	 */
	Timer timer;
	
	/**
	 * This task timeouts pending requests. The task is created upon async service request.
	 * "requests" is synchronized when timeoutPendingRequests is modified.
	 */
	AtomicReference<TimerTask> timeoutPendingRequestsTask = new AtomicReference<TimerTask>(null);
	
	/** Encoder Context */
	EncoderContext encoderCtx;
	
	AtomicInteger secureChannelIdCounter = new AtomicInteger(); 

	/** Selection of cipher suites, an intersecion of available and the suites in the algorithm */ 
	String[] cipherSuites;
	
	/**
	 * <p>Constructor for HttpsClient.</p>
	 *
	 * @param protocol a {@link java.lang.String} object.
	 */
	public HttpsClient(String protocol) {
		if ( !protocol.equals( UriUtil.SCHEME_HTTP ) && !protocol.equals( UriUtil.SCHEME_HTTPS ) ) throw new IllegalArgumentException();
		this.protocol = protocol;
	}
	
	/**
	 * Set client connection manager. Call before #initialize.
	 * If ClientConnectionManager is not set, a default implementation is used
	 *
	 * @param ccm a {@link PoolingHttpClientConnectionManager} object.
	 */
	public void setClientConnectionManager(PoolingHttpClientConnectionManager ccm)
	{
		this.ccm = ccm;
	}
	
	/**
	 * Set the number of concurrent maximum connections. Call this before calling #initialize.
	 * This value applies only if ClientConnectionManager has not been overridden.
	 *
	 * @param maxConnections a int.
	 */
	public void setMaxConnections(int maxConnections) {
		this.maxConnections = maxConnections;
	}
	
	/**
	 * {@inheritDoc}
	 *
	 * Initialize HttpsClient.
	 */
	public void initialize(String connectUrl, TransportChannelSettings tcs, EncoderContext ctx) throws ServiceResultException {
		
		this.connectUrl = connectUrl;
		this.securityPolicyUri = tcs.getDescription().getSecurityPolicyUri();
		this.transportChannelSettings = tcs;
		HttpsSettings httpsSettings = tcs.getHttpsSettings();
		securityPolicies = httpsSettings.getHttpsSecurityPolicies();
		if(securityPolicies == null || securityPolicies.length == 0) {
			throw new ServiceResultException( StatusCodes.Bad_SecurityChecksFailed, "No HttpsSecurityPolicies defined");
		}
				
		if (logger.isDebugEnabled()) {
			logger.debug("initialize: url={}; settings={}", tcs.getDescription().getEndpointUrl(), ObjectUtils.printFields(tcs));
		}
			
    	// Setup Encoder
		EndpointConfiguration endpointConfiguration = tcs.getConfiguration();
		encoderCtx = ctx;
		encoderCtx.setMaxArrayLength( endpointConfiguration.getMaxArrayLength() != null ? endpointConfiguration.getMaxArrayLength() : 0 );
		encoderCtx.setMaxStringLength( endpointConfiguration.getMaxStringLength() != null ? endpointConfiguration.getMaxStringLength() : 0 );
		encoderCtx.setMaxByteStringLength( endpointConfiguration.getMaxByteStringLength() != null ? endpointConfiguration.getMaxByteStringLength() : 0 );
		encoderCtx.setMaxMessageSize( endpointConfiguration.getMaxMessageSize()!=null ? endpointConfiguration.getMaxMessageSize() : 0 );
		
		timer = TimerUtil.getTimer();
		try {
			Registry<ConnectionSocketFactory> sr;
			if ( protocol.equals( UriUtil.SCHEME_HTTPS ) ) {
		        
			  SSLContext sslcontext;
			  String[] supportedProtocols = { "TLSv1.1", "TLSv1.2", "TLSv1.3" };
				try{
					sslcontext = SSLContext.getInstance("TLSv1.3");
				}catch(NoSuchAlgorithmException ex) {
					/*
					 * Try first create tls 1.2 supporting context.
					 * This should work at least on java 8 out of the box.
					 * Might work on java 7 if tls 1.2 is enabled.
					 */
					try {
						supportedProtocols = new String[] { "TLSv1.1", "TLSv1.2" };
						sslcontext = SSLContext.getInstance("TLSv1.2");
					} catch (NoSuchAlgorithmException x) {
						//fallback option
						supportedProtocols = new String[] { "TLSv1.1"  };
						logger.debug("No TLSv1.2 implementation found, trying TLS");
						sslcontext = SSLContext.getInstance("TLSv1.1");
					}
				}
		        
		        sslcontext.init( httpsSettings.getKeyManagers(), httpsSettings.getTrustManagers(), null );

				HostnameVerifier hostnameVerifier = httpsSettings.getHostnameVerifier() != null ?
						httpsSettings.getHostnameVerifier() : NoopHostnameVerifier.INSTANCE;


				SSLEngine sslEngine = sslcontext.createSSLEngine();
				String[] enabledCipherSuites = sslEngine.getEnabledCipherSuites();
				
				Set<String> policiesCipherSuitesCombinations = new HashSet<String>();
				for(HttpsSecurityPolicy hsp : securityPolicies) {
                    policiesCipherSuitesCombinations.addAll(Arrays.asList(hsp.getCipherSuites()));
				}
				
				cipherSuites = CryptoUtil.filterCipherSuiteList(enabledCipherSuites, policiesCipherSuitesCombinations.toArray(new String[0]));
				
				logger.info( "Enabled protocols in SSL Engine are {}", Arrays.toString( sslEngine.getEnabledProtocols()));
				logger.info( "Enabled CipherSuites in SSL Engine are {}", Arrays.toString( enabledCipherSuites ) );
				logger.info( "Client CipherSuite selection for {} is {}", Arrays.toString(securityPolicies), Arrays.toString( cipherSuites ));

				SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
						sslcontext, supportedProtocols, cipherSuites, hostnameVerifier);

				sr = RegistryBuilder.<ConnectionSocketFactory> create()
						.register("https", sf)
						.build();

			}
			else {
				sr = RegistryBuilder.<ConnectionSocketFactory> create()
						.register("http", PlainConnectionSocketFactory.getSocketFactory())
						.build();
			}



			if ( ccm == null ) {
				ccm = new PoolingHttpClientConnectionManager(sr);
				ccm.setMaxTotal( maxConnections );
				ccm.setDefaultMaxPerRoute( maxConnections );
			}

			RequestConfig config = RequestConfig.custom()
					.setConnectionRequestTimeout(transportChannelSettings.getConfiguration().getOperationTimeout(), TimeUnit.MILLISECONDS)
					.setResponseTimeout(transportChannelSettings.getConfiguration().getOperationTimeout(), TimeUnit.MILLISECONDS)
					.build();

			HttpClientBuilder clientBuilder = HttpClients.custom()
					.setConnectionManager(ccm)
					.setDefaultRequestConfig(config);


			
			// Set username and password authentication
			if ( httpsSettings.getUsername()!=null && httpsSettings.getPassword()!=null ) {
				BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
				credentialsProvider.setCredentials(
	        	    new AuthScope(null, -1),
	        	    new UsernamePasswordCredentials(httpsSettings.getUsername(), httpsSettings.getPassword().toCharArray()));
	        	clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
			}

			httpclient = clientBuilder.build();

		} catch (NoSuchAlgorithmException | KeyManagementException e) {
			throw new ServiceResultException( e );
		}

    }
	
	long getTimeout(ServiceRequest serviceRequest) {
		UnsignedInteger timeoutHint = serviceRequest.getRequestHeader() != null ? serviceRequest.getRequestHeader().getTimeoutHint() : null;
		long clientTimeout = timeoutHint != null ? timeoutHint.longValue() : getOperationTimeout();
		if ( clientTimeout == 0 ) clientTimeout = 100000L;
		return clientTimeout;
	}
	
	/** {@inheritDoc} */
	@Override
	public ServiceResponse serviceRequest(ServiceRequest request) throws ServiceResultException {
		return serviceRequest(request, getTimeout(request));
	}
	
	/** {@inheritDoc} */
	@Override
	public ServiceResponse serviceRequest(ServiceRequest request, long operationTimeout) throws ServiceResultException {
		AsyncResult<ServiceResponse> result = serviceRequestAsync( request );
		return (ServiceResponse) result.waitForResult(operationTimeout, TimeUnit.MILLISECONDS);
	}

	/** {@inheritDoc} */
	@Override
	public AsyncResult<ServiceResponse> serviceRequestAsync(ServiceRequest serviceRequest) {
		return serviceRequestAsync(serviceRequest, getTimeout(serviceRequest));
	}
	
	/** {@inheritDoc} */
	@Override
	public AsyncResult<ServiceResponse> serviceRequestAsync(ServiceRequest serviceRequest, long operationTimeout) {
		return serviceRequestAsync( serviceRequest, operationTimeout, -1);
	}

	/**
	 * <p>serviceRequestAsync.</p>
	 *
	 * @param serviceRequest a {@link org.opcfoundation.ua.builtintypes.ServiceRequest} object.
	 * @param operationTimeout a long.
	 * @param secureChannelId a int.
	 * @return a {@link org.opcfoundation.ua.transport.AsyncResult} object.
	 */
	public AsyncResult<ServiceResponse> serviceRequestAsync(ServiceRequest serviceRequest, long operationTimeout, int secureChannelId) {
		HttpsClientPendingRequest pendingRequest = new HttpsClientPendingRequest(this, serviceRequest);
		pendingRequest.secureChannelId = secureChannelId;
		pendingRequest.securityPolicy = securityPolicyUri;
		pendingRequest.requestId = requestIdCounter.getAndIncrement();
		
		logger.debug("serviceRequestAsync: Sending message, requestId={} message={} operationTimeout={}", pendingRequest.requestId, serviceRequest.getClass().getSimpleName(), operationTimeout);
		
		logger.trace("serviceRequestAsync: message={}", serviceRequest);
		
		requests.put( pendingRequest.requestId, pendingRequest );
		if (pendingRequest.startTime!=0) scheduleTimeoutRequestsTimer();
		executor.execute( pendingRequest );
		return pendingRequest.result;
	}
	
	/**
	 * <p>close.</p>
	 */
	public void close() {
		ccm.close();
				
		// Cancel all pending requests
		{
			Collection<HttpsClientPendingRequest> copy;
				
			// Cancel timeout task
			cancelTimeoutPendingRequestTask();

			// TODO: Is this thread safe? Does it have to be? Should requests be a BlockingQueue?
			
//			if (requests.isEmpty())
//				copy = Collections.emptyList();
//			else
			synchronized(requests) {
				copy = new ArrayList<HttpsClientPendingRequest>(requests.values());
				logger.debug("requests.clear()");
				requests.clear();
			}

			if (!copy.isEmpty()) {
				for (HttpsClientPendingRequest pr : copy) {
					pr.cancel();
				}
			}
		}		
	}

	/** {@inheritDoc} */
	@Override
	public void dispose() {
		close();
		ccm = null;
		sr = null;
		httpclient = null;
		serializer = null;
		transportChannelSettings = null;
	}

	/** {@inheritDoc} */
	@Override
	public EnumSet<TransportChannelFeature> getSupportedFeatures() {
		return EnumSet.of(
				TransportChannelFeature.open, 
				TransportChannelFeature.openAsync, 
				TransportChannelFeature.close, 
				TransportChannelFeature.closeAync, 
				TransportChannelFeature.sendRequest, 
				TransportChannelFeature.sendRequestAsync);
	}

	/** {@inheritDoc} */
	@Override
	public EndpointDescription getEndpointDescription() {
		return transportChannelSettings.getDescription();
	}

	/** {@inheritDoc} */
	@Override
	public EndpointConfiguration getEndpointConfiguration() {
		return transportChannelSettings.getConfiguration();
	}

	/** {@inheritDoc} */
	@Override
	public EncoderContext getMessageContext() {
		return encoderCtx;
	}

	/** {@inheritDoc} */
	@Override
	public void setOperationTimeout(int timeout) {
		transportChannelSettings.getConfiguration().setOperationTimeout(timeout);
	}

	/** {@inheritDoc} */
	@Override
	public int getOperationTimeout() {
		Integer i = transportChannelSettings.getConfiguration().getOperationTimeout();		
		return i == null ? 0 : i;
	}

	
	
	
	

	/**
	 * Sets new Timer Task that timeouts pending requests.
	 * If task already exists but is too far in the future, it is canceled and new task assigned
	 */
	private void scheduleTimeoutRequestsTimer()	{
		HttpsClientPendingRequest nextRequest = _getNextTimeoutingPendingRequest();
		
		// Cancel task
		if (nextRequest == null) {
			cancelTimeoutPendingRequestTask();
		} else {
			TimerTask task = timeoutPendingRequestsTask.get();
			// Task does not exists or is not ok
			if (task == null || task.scheduledExecutionTime() > nextRequest.timeoutTime) {
				cancelTimeoutPendingRequestTask();
				// Create a new task
				task = TimerUtil.schedule(timer, timeoutRun, executor,
						nextRequest.timeoutTime);
				if (!timeoutPendingRequestsTask.compareAndSet(null, task))
					// it was already set
					task.cancel();
			}
		}
	}
		
	/**
	 * This runnable goes thru pending requests and sets Bad_Timeout error code to all 
	 * requests that have timeouted. 
	 */
	Runnable timeoutRun = new Runnable() {
		@Override
		public void run() {
			cancelTimeoutPendingRequestTask();
			synchronized(requests) {
				long currentTime = System.currentTimeMillis();
				for (HttpsClientPendingRequest req : requests.values()) {
					if (req.timeoutTime!=0 && currentTime >= req.timeoutTime) {
						long elapsed = System.currentTimeMillis()-req.startTime;
						long timeOutAt = req.timeoutTime - req.startTime;
						logger.warn("Request id={} msg={} timeouted {} ms elapsed. timeout at {} ms", req.requestId, req.requestMessage.getClass(), elapsed, timeOutAt);
						req.timeout();
					}
				}
			}
			// Schedule next timeout event
			scheduleTimeoutRequestsTimer();
		}};

	private void cancelTimeoutPendingRequestTask() {
		TimerTask task = timeoutPendingRequestsTask.getAndSet(null);
		if (task !=null) {
			task.cancel();
		}
	}
		
		
	/**
	 * Get the next request that is closest to timeout
	 * 
	 * @return null or request
	 */
	private HttpsClientPendingRequest _getNextTimeoutingPendingRequest() {
		long next = Long.MAX_VALUE;
		HttpsClientPendingRequest result = null;
		synchronized (requests) {
			for (HttpsClientPendingRequest req : requests.values()) {
				if (next > req.timeoutTime) {
					next = req.timeoutTime;
					result = req;
					break;
				}
			}
		}
		return result;
	}

}
