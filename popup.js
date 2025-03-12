document.addEventListener('DOMContentLoaded', function() {
  const techListElement = document.getElementById('tech-list');
  const loadingElement = document.getElementById('loading');
  
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    const activeTab = tabs[0];
    chrome.scripting.executeScript({
      target: {tabId: activeTab.id},
      function: detectTechnologies
    }, function(results) {
      loadingElement.style.display = 'none';
      
      if (results && results[0] && results[0].result) {
        const technologies = results[0].result;
        
        if (technologies.length === 0) {
          techListElement.innerHTML = '<div class="no-tech">Nessuna tecnologia rilevata</div>';
          return;
        }
        
        // Raggruppa tecnologie per categoria
        const categories = {};
        technologies.forEach(tech => {
          if (!categories[tech.category]) {
            categories[tech.category] = [];
          }
          categories[tech.category].push(tech);
        });
        
        // Ordine predefinito per le categorie
        const categoryOrder = [
          'Web Server',
          'Server', 
          'Proxy',
          'Cache Tool',
          'CDN', 
          'CMS', 
          'JavaScript Framework',
          'JavaScript Library', 
          'CSS Framework',
          'Linguaggio di programmazione', 
          'PHP', 
          'Database', 
          'Analytics', 
          'Tag Manager',
          'Marketing',
          'Network Pubblicitario',
          'E-commerce', 
          'Security',
          'Static Site Generator',
          'Strumenti di Sviluppo',
          'PaaS',
          'PWA',
          'Font',
          'RUM',
          'Personalisation',
          'Segmentation',
          'Customer data platform',
          'Miscellanea',
          'Altro'
        ];
        
        // Aggiungi tecnologie al DOM, ordinate per categoria
        categoryOrder.forEach(category => {
          if (categories[category] && categories[category].length > 0) {
            // Crea elemento categoria
            const categoryElem = document.createElement('div');
            categoryElem.className = 'category';
            categoryElem.textContent = category;
            
            // Aggiungi conteggio
            const countSpan = document.createElement('span');
            countSpan.className = 'tech-count';
            countSpan.textContent = categories[category].length;
            categoryElem.appendChild(countSpan);
            
            techListElement.appendChild(categoryElem);
            
            // Aggiungi le tecnologie di questa categoria, ordinate alfabeticamente
            categories[category]
              .sort((a, b) => a.name.localeCompare(b.name))
              .forEach(tech => {
                const techItem = document.createElement('div');
                techItem.className = 'tech-item';
                
                const techName = document.createElement('span');
                techName.className = 'tech-name';
                techName.textContent = tech.name;
                
                techItem.appendChild(techName);
                
                if (tech.version) {
                  const techVersion = document.createElement('span');
                  techVersion.className = 'tech-version';
                  techVersion.textContent = tech.version;
                  techItem.appendChild(techVersion);
                }
                
                const techType = document.createElement('span');
                techType.className = 'tech-type';
                techType.textContent = tech.type || '';
                techItem.appendChild(techType);
                
                techListElement.appendChild(techItem);
              });
          }
        });
        
        // Aggiungi eventuali categorie non ordinate
        Object.keys(categories).forEach(category => {
          if (!categoryOrder.includes(category) && categories[category].length > 0) {
            // Crea elemento categoria
            const categoryElem = document.createElement('div');
            categoryElem.className = 'category';
            categoryElem.textContent = category;
            
            // Aggiungi conteggio
            const countSpan = document.createElement('span');
            countSpan.className = 'tech-count';
            countSpan.textContent = categories[category].length;
            categoryElem.appendChild(countSpan);
            
            techListElement.appendChild(categoryElem);
            
            // Aggiungi le tecnologie di questa categoria
            categories[category]
              .sort((a, b) => a.name.localeCompare(b.name))
              .forEach(tech => {
                const techItem = document.createElement('div');
                techItem.className = 'tech-item';
                
                const techName = document.createElement('span');
                techName.className = 'tech-name';
                techName.textContent = tech.name;
                
                techItem.appendChild(techName);
                
                if (tech.version) {
                  const techVersion = document.createElement('span');
                  techVersion.className = 'tech-version';
                  techVersion.textContent = tech.version;
                  techItem.appendChild(techVersion);
                }
                
                const techType = document.createElement('span');
                techType.className = 'tech-type';
                techType.textContent = tech.type || '';
                techItem.appendChild(techType);
                
                techListElement.appendChild(techItem);
              });
          }
        });
      } else {
        techListElement.innerHTML = '<div class="no-tech">Errore durante l\'analisi</div>';
      }
    });
  });
});

// Funzione che viene eseguita nella pagina web per rilevare le tecnologie
function detectTechnologies() {
  const technologies = [];
  
  // --- RILEVAMENTO WEB SERVER ---
  function detectWebServer() {
    // Prova a rilevare il server dai meta tag
    const serverHeader = document.querySelector('meta[name="server"], meta[name="generator"]');
    const poweredByHeader = document.querySelector('meta[http-equiv="X-Powered-By"], meta[name="powered-by"]');
    
    // Esamina i commenti HTML per le informazioni sul server
    const htmlContent = document.documentElement.outerHTML;
    
    // Apache
    if ((serverHeader && serverHeader.getAttribute('content') && 
         serverHeader.getAttribute('content').includes('Apache')) || 
        htmlContent.includes('Apache')) {
      
      let version = null;
      if (serverHeader) {
        const versionMatch = serverHeader.getAttribute('content').match(/Apache\/(\d+\.\d+\.\d+)/);
        if (versionMatch) version = versionMatch[1];
      }
      
      technologies.push({
        name: 'Apache',
        version: version,
        type: 'Web Server',
        category: 'Web Server'
      });
    }
    
    // Nginx
    if ((serverHeader && serverHeader.getAttribute('content') && 
         serverHeader.getAttribute('content').includes('nginx')) || 
        htmlContent.includes('nginx')) {
      
      let version = null;
      if (serverHeader) {
        const versionMatch = serverHeader.getAttribute('content').match(/nginx\/(\d+\.\d+\.\d+)/);
        if (versionMatch) version = versionMatch[1];
      }
      
      technologies.push({
        name: 'Nginx',
        version: version,
        type: 'Web Server',
        category: 'Web Server'
      });
    }
    
    // IIS
    if ((serverHeader && serverHeader.getAttribute('content') && 
         serverHeader.getAttribute('content').includes('Microsoft-IIS')) || 
        htmlContent.includes('IIS')) {
      
      let version = null;
      if (serverHeader) {
        const versionMatch = serverHeader.getAttribute('content').match(/Microsoft-IIS\/(\d+\.\d+)/);
        if (versionMatch) version = versionMatch[1];
      }
      
      technologies.push({
        name: 'IIS',
        version: version,
        type: 'Web Server',
        category: 'Web Server'
      });
    }
    
    // LiteSpeed
    if ((serverHeader && serverHeader.getAttribute('content') && 
         serverHeader.getAttribute('content').includes('LiteSpeed')) || 
        htmlContent.includes('LiteSpeed')) {
      
      let version = null;
      if (serverHeader) {
        const versionMatch = serverHeader.getAttribute('content').match(/LiteSpeed\/(\d+\.\d+)/);
        if (versionMatch) version = versionMatch[1];
      }
      
      technologies.push({
        name: 'LiteSpeed',
        version: version,
        type: 'Web Server',
        category: 'Web Server'
      });
    }
    
    // Controlla anche Tomcat, Jetty, Node.js come server
    if (htmlContent.includes('Tomcat') || htmlContent.includes('Apache Tomcat')) {
      technologies.push({
        name: 'Apache Tomcat',
        type: 'Application Server',
        category: 'Web Server'
      });
    }
    
    if (htmlContent.includes('Jetty') || htmlContent.includes('Eclipse Jetty')) {
      technologies.push({
        name: 'Jetty',
        type: 'Application Server',
        category: 'Web Server'
      });
    }
    
    // Proxy Server
    if (document.querySelector('meta[name="proxy"], meta[name="via"]') || 
        htmlContent.includes('proxy_pass') || 
        htmlContent.includes('X-Forwarded-For')) {
      technologies.push({
        name: 'Proxy Server',
        type: 'Web Proxy',
        category: 'Proxy'
      });
    }
    
    // Verifica Next.js anche come web server
    if (document.getElementById('__next') || 
        document.querySelector('script[data-next-page]') ||
        htmlContent.includes('__NEXT_DATA__')) {
      
      let version = null;
      // Cerca di estrarre la versione di Next.js
      const nextScript = document.querySelector('script#__NEXT_DATA__');
      if (nextScript) {
        try {
          const nextData = JSON.parse(nextScript.textContent);
          if (nextData && nextData.buildId) {
            // Cerchiamo nei commenti HTML o nel codice sorgente per la versione
            const nextVersionMatch = htmlContent.match(/next\/static\/(\d+\.\d+\.\d+)/);
            if (nextVersionMatch) {
              version = nextVersionMatch[1];
            }
          }
        } catch (e) {
          // Possiamo ignorare gli errori di parsing
        }
      }
      
      technologies.push({
        name: 'Next.js',
        version: version,
        type: 'Framework Server',
        category: 'Web Server'
      });
    }
    
    // HTTP/3 (QUIC)
    if (document.querySelector('meta[http-equiv="alt-svc"]') || 
        htmlContent.includes('h3=":443"') || 
        htmlContent.includes('HTTP/3')) {
      technologies.push({
        name: 'HTTP/3',
        type: 'Protocol',
        category: 'Web Server'
      });
    }
  }
  
  // --- RILEVAMENTO CACHE TOOLS ---
  function detectCacheTools() {
    const htmlContent = document.documentElement.outerHTML;
    
    // Varnish
    if (document.querySelector('meta[name="varnish"], meta[name="x-cache"]') ||
        htmlContent.includes('X-Varnish') || 
        document.cookie.includes('varnish')) {
      technologies.push({
        name: 'Varnish',
        type: 'HTTP Cache',
        category: 'Cache Tool'
      });
    }
    
    // Redis (anche se spesso è invisibile lato client)
    if (htmlContent.includes('redis') || htmlContent.includes('Redis')) {
      technologies.push({
        name: 'Redis',
        type: 'Cache',
        category: 'Cache Tool'
      });
    }
    
    // Memcached
    if (htmlContent.includes('memcached') || htmlContent.includes('Memcached')) {
      technologies.push({
        name: 'Memcached',
        type: 'Cache',
        category: 'Cache Tool'
      });
    }
    
    // Cloudflare Cache
    if (document.querySelector('meta[name="cf-cache-status"]') ||
        htmlContent.includes('cf-edge') || 
        document.cookie.includes('__cflb') ||
        document.querySelector('script[src*="cloudflare"]')) {
      technologies.push({
        name: 'Cloudflare Cache',
        type: 'Edge Cache',
        category: 'Cache Tool'
      });
    }
  }
  
  // --- RILEVAMENTO CDN ---
  function detectCDN() {
    const htmlContent = document.documentElement.outerHTML;
    
    // Cloudflare
    if (document.querySelector('script[src*="cloudflare.com"]') || 
        document.querySelector('meta[name="cf-ray"]') ||
        htmlContent.includes('cloudflare') ||
        document.cookie.includes('__cfduid')) {
      technologies.push({
        name: 'Cloudflare',
        type: 'CDN',
        category: 'CDN'
      });
    }
    
    // Akamai
    if (document.querySelector('script[src*="akamai"]') || 
        document.cookie.includes('akamai') ||
        htmlContent.includes('Akamai') ||
        htmlContent.includes('akamaiedge.net')) {
      technologies.push({
        name: 'Akamai',
        type: 'CDN',
        category: 'CDN'
      });
    }
    
    // Fastly
    if (document.querySelector('meta[name="fastly"]') ||
        htmlContent.includes('Fastly') ||
        htmlContent.includes('fastly.net') ||
        document.cookie.includes('fastly')) {
      technologies.push({
        name: 'Fastly',
        type: 'CDN',
        category: 'CDN'
      });
    }
    
    // Amazon CloudFront
    if (document.querySelector('script[src*="cloudfront.net"]') ||
        htmlContent.includes('cloudfront.net') ||
        document.cookie.includes('CloudFront')) {
      technologies.push({
        name: 'Amazon CloudFront',
        type: 'CDN',
        category: 'CDN'
      });
    }
    
    // jsDelivr
    if (document.querySelector('script[src*="jsdelivr.net"]') ||
        document.querySelector('link[href*="jsdelivr.net"]') ||
        htmlContent.includes('jsdelivr.net')) {
      technologies.push({
        name: 'jsDelivr',
        type: 'CDN',
        category: 'CDN'
      });
    }
    
    // CDNJS (Cloudflare)
    if (document.querySelector('script[src*="cdnjs.cloudflare.com"]') ||
        document.querySelector('link[href*="cdnjs.cloudflare.com"]')) {
      technologies.push({
        name: 'CDNJS',
        type: 'CDN',
        category: 'CDN'
      });
    }
    
    // StackPath
    if (document.querySelector('script[src*="stackpathcdn.com"]') ||
        htmlContent.includes('StackPath') ||
        htmlContent.includes('stackpathcdn')) {
      technologies.push({
        name: 'StackPath',
        type: 'CDN',
        category: 'CDN'
      });
    }
  }
  
  // --- RILEVAMENTO CMS ---
  function detectCMS() {
    const htmlContent = document.documentElement.outerHTML;
    
    // WordPress
    if (document.querySelector('meta[name="generator"][content*="WordPress"]') || 
        document.querySelectorAll('link[rel="https://api.w.org/"]').length > 0 ||
        window.wp || 
        document.body.classList.contains('wp-') ||
        document.getElementById('wpadminbar') ||
        htmlContent.includes('/wp-content/') ||
        htmlContent.includes('/wp-includes/')) {
      
      let version = null;
      const metaGen = document.querySelector('meta[name="generator"][content*="WordPress"]');
      if (metaGen) {
        const match = metaGen.getAttribute('content').match(/WordPress\s+(\d+\.\d+(\.\d+)?)/i);
        if (match) version = match[1];
      }
      
      technologies.push({
        name: 'WordPress',
        version: version,
        type: 'CMS',
        category: 'CMS'
      });
      
      // Controlla temi e plugin WordPress
      if (window.wp && window.wp.theme) {
        technologies.push({
          name: window.wp.theme.name || 'WordPress Theme',
          version: window.wp.theme.version,
          type: 'Tema WP',
          category: 'CMS'
        });
      }
      
      // WooCommerce
      if (document.querySelector('.woocommerce') || 
          document.body.classList.contains('woocommerce') || 
          document.querySelector('div[class*="woocommerce"]') ||
          htmlContent.includes('woocommerce')) {
        
        let version = null;
        const wooMatch = htmlContent.match(/woocommerce\/(\d+\.\d+\.\d+)/i);
        if (wooMatch) version = wooMatch[1];
        
        technologies.push({
          name: 'WooCommerce',
          version: version,
          type: 'E-commerce',
          category: 'E-commerce'
        });
      }
    }
    
    // Drupal
    if (document.querySelector('meta[name="generator"][content*="Drupal"]') || 
        window.Drupal ||
        document.querySelector('[class*="drupal-"]') ||
        htmlContent.includes('/sites/all/themes/') ||
        htmlContent.includes('/sites/all/modules/')) {
      
      let version = null;
      const metaGen = document.querySelector('meta[name="generator"][content*="Drupal"]');
      if (metaGen) {
        const match = metaGen.getAttribute('content').match(/Drupal\s+(\d+)/i);
        if (match) version = match[1];
      }
      
      technologies.push({
        name: 'Drupal',
        version: version,
        type: 'CMS',
        category: 'CMS'
      });
    }
    
    // Joomla
    if (document.querySelector('meta[name="generator"][content*="Joomla"]') || 
        window.Joomla ||
        htmlContent.includes('/components/com_')) {
      
      let version = null;
      const metaGen = document.querySelector('meta[name="generator"][content*="Joomla"]');
      if (metaGen) {
        const match = metaGen.getAttribute('content').match(/Joomla!\s+(\d+\.\d+)/i);
        if (match) version = match[1];
      }
      
      technologies.push({
        name: 'Joomla',
        version: version,
        type: 'CMS',
        category: 'CMS'
      });
    }
    
    // Magento
    if (document.querySelector('meta[name="generator"][content*="Magento"]') || 
        window.Mage ||
        htmlContent.includes('Mage.Cookies') ||
        document.querySelector('script[src*="mage/cookies"]')) {
      
      let version = null;
      const metaGen = document.querySelector('meta[name="generator"][content*="Magento"]');
      if (metaGen) {
        const match = metaGen.getAttribute('content').match(/Magento\s+(\d+\.\d+)/i);
        if (match) version = match[1];
      }
      
      technologies.push({
        name: 'Magento',
        version: version,
        type: 'E-commerce',
        category: 'E-commerce'
      });
    }
    
    // Shopify
    if (window.Shopify || 
        document.querySelector('link[rel="canonical"][href*="shopify.com"]') ||
        document.querySelector('meta[property="shopify:*"]') ||
        htmlContent.includes('Shopify.theme') ||
        document.querySelector('link[href*="cdn.shopify.com"]')) {
      technologies.push({
        name: 'Shopify',
        type: 'E-commerce',
        category: 'E-commerce'
      });
    }
    
    // Ghost
    if (document.querySelector('meta[name="generator"][content*="Ghost"]') ||
        htmlContent.includes('ghost-theme') ||
        document.querySelector('link[rel="alternate"][type="application/rss+xml"][href*="ghost.io"]')) {
      
      let version = null;
      const metaGen = document.querySelector('meta[name="generator"][content*="Ghost"]');
      if (metaGen) {
        const match = metaGen.getAttribute('content').match(/Ghost\s+(\d+\.\d+)/i);
        if (match) version = match[1];
      }
      
      technologies.push({
        name: 'Ghost',
        version: version,
        type: 'CMS',
        category: 'CMS'
      });
    }
    
    // Contentful
    if (document.querySelector('meta[name="generator"][content*="Contentful"]') ||
        htmlContent.includes('ctfl-') ||
        htmlContent.includes('contentful')) {
      technologies.push({
        name: 'Contentful',
        type: 'Headless CMS',
        category: 'CMS'
      });
    }
    
    // Strapi
    if (htmlContent.includes('strapi') ||
        htmlContent.includes('Strapi') ||
        document.querySelector('meta[name="generator"][content*="Strapi"]')) {
      technologies.push({
        name: 'Strapi',
        type: 'Headless CMS',
        category: 'CMS'
      });
    }
  }
  
  // --- RILEVAMENTO FRAMEWORK JS ---
  function detectJSFrameworks() {
    const htmlContent = document.documentElement.outerHTML;
    
    // Angular
    if (window.angular || 
        document.querySelector('[ng-app], [ng-controller], [ng-model]') || 
        document.querySelector('.ng-binding, .ng-scope') ||
        document.querySelector('script[src*="angular.js"], script[src*="angular.min.js"]')) {
      
      let version = window.angular ? window.angular.version.full : null;
      if (!version) {
        const angularVersionMatch = htmlContent.match(/angular[.-](\d+\.\d+\.\d+)/i);
        if (angularVersionMatch) version = angularVersionMatch[1];
      }
      
      technologies.push({
        name: 'Angular',
        version: version,
        type: 'Framework',
        category: 'JavaScript Framework'
      });
    }
    
    // React
    if (window.React || 
        document.querySelector('[data-reactid], [data-react-checksum]') ||
        document.querySelector('script[src*="react.js"], script[src*="react.min.js"], script[src*="react.production.min.js"]') ||
        Array.from(document.querySelectorAll('*')).some(e => 
          Object.keys(e).some(key => key.includes('__reactInternalInstance$') || 
                                     key.includes('__reactFiber$')))) {
      
      let version = window.React ? window.React.version : null;
      if (!version) {
        const reactVersionMatch = htmlContent.match(/react@(\d+\.\d+\.\d+)/i);
        if (reactVersionMatch) version = reactVersionMatch[1];
      }
      
      technologies.push({
        name: 'React',
        version: version,
        type: 'Framework',
        category: 'JavaScript Framework'
      });
    }
    
    // Vue.js
    if (window.Vue || 
        document.querySelector('[data-v-app], [data-v-component]') ||
        document.querySelector('script[src*="vue.js"], script[src*="vue.min.js"]') ||
        Array.from(document.querySelectorAll('*')).some(el => el.__vue__)) {
      
      let version = window.Vue ? window.Vue.version : null;
      if (!version) {
        const vueVersionMatch = htmlContent.match(/vue@(\d+\.\d+\.\d+)/i);
        if (vueVersionMatch) version = vueVersionMatch[1];
      }
      
      technologies.push({
        name: 'Vue.js',
        version: version,
        type: 'Framework',
        category: 'JavaScript Framework'
      });
    }
    
    // Svelte
    if (document.querySelector('style[data-svelte]') ||
        htmlContent.includes('svelte-') ||
        document.querySelector('script[src*="svelte"]')) {
      
      let version = null;
      const svelteVersionMatch = htmlContent.match(/svelte\/([\d.]+)/i);
      if (svelteVersionMatch) version = svelteVersionMatch[1];
      
      technologies.push({
        name: 'Svelte',
        type: 'Framework',
        category: 'JavaScript Framework'
      });
    }
    
    // Next.js
    if (document.getElementById('__next') || 
        document.querySelector('script[data-next-page]') ||
        htmlContent.includes('__NEXT_DATA__')) {
      
      let version = null;
      const nextVersionMatch = htmlContent.match(/next\/static\/([\d.]+)/i);
      if (nextVersionMatch) version = nextVersionMatch[1];
      
      technologies.push({
        name: 'Next.js',
        version: version,
        type: 'Framework',
        category: 'JavaScript Framework'
      });
    }
    
    // Gatsby
    if (window.___gatsby || 
        document.getElementById('___gatsby') ||
        htmlContent.includes('gatsby-') ||
        document.querySelector('meta[name="generator"][content*="Gatsby"]')) {
      
      let version = null;
      const gatsbyVersionMatch = htmlContent.match(/gatsby@([\d.]+)/i);
      if (gatsbyVersionMatch) version = gatsbyVersionMatch[1];
      
      technologies.push({
        name: 'Gatsby',
        version: version,
        type: 'Framework',
        category: 'JavaScript Framework'
      });
    }
    
    // Nuxt.js
    if (window.__NUXT__ || 
        document.getElementById('__nuxt') ||
        htmlContent.includes('nuxt-') ||
        document.querySelector('script[src*="nuxt"]')) {
      
      let version = null;
      const nuxtVersionMatch = htmlContent.match(/nuxt\/([\d.]+)/i);
      if (nuxtVersionMatch) version = nuxtVersionMatch[1];
      
      technologies.push({
        name: 'Nuxt.js',
        version: version,
        type: 'Framework',
        category: 'JavaScript Framework'
      });
    }
    
    // Ember.js
    if (window.Ember ||
        htmlContent.includes('ember-') ||
        document.querySelector('script[src*="ember"]')) {
      
      let version = window.Ember ? window.Ember.VERSION : null;
      if (!version) {
        const emberVersionMatch = htmlContent.match(/ember[.-]([\d.]+)/i);
        if (emberVersionMatch) version = emberVersionMatch[1];
      }
      
      technologies.push({
        name: 'Ember.js',
        version: version,
        type: 'Framework',
        category: 'JavaScript Framework'
      });
    }
    
    // Alpine.js
    if (document.querySelector('[x-data], [x-bind], [x-on]') ||
        htmlContent.includes('alpine.js') ||
        document.querySelector('script[src*="alpine"]')) {
      
      let version = null;
      const alpineVersionMatch = htmlContent.match(/alpine@([\d.]+)/i);
      if (alpineVersionMatch) version = alpineVersionMatch[1];
      
      technologies.push({
        name: 'Alpine.js',
        type: 'Framework',
        category: 'JavaScript Framework'
      });
    }
    
    // Emotion
    if (document.querySelector('style[data-emotion]') ||
        htmlContent.includes('data-emotion') ||
        document.querySelector('script[src*="emotion"]')) {
      technologies.push({
        name: 'Emotion',
        type: 'CSS-in-JS',
        category: 'JavaScript Framework'
      });
    }
  }
  
  // --- RILEVAMENTO LIBRERIE JS ---
  function detectJSLibraries() {
    const htmlContent = document.documentElement.outerHTML;
    
    // jQuery
    if (window.jQuery || window.$ ||
        document.querySelector('script[src*="jquery"]')) {
      
      let version = window.jQuery ? jQuery.fn.jquery : null;
      if (!version) {
        const jQueryVersionMatch = htmlContent.match(/jquery[.-]([\d.]+)/i);
        if (jQueryVersionMatch) version = jQueryVersionMatch[1];
      }
      
      technologies.push({
        name: 'jQuery',
        version: version,
        type: 'DOM Manipulation',
        category: 'JavaScript Library'
      });
    }
    
    // Lodash
    if (window._ && _.VERSION ||
        document.querySelector('script[src*="lodash"]')) {
      
      let version = window._ && _.VERSION ? _.VERSION : null;
      if (!version) {
        const lodashVersionMatch = htmlContent.match(/lodash@([\d.]+)/i);
        if (lodashVersionMatch) version = lodashVersionMatch[1];
      }
      
      technologies.push({
        name: 'Lodash',
        version: version,
        type: 'Utility',
        category: 'JavaScript Library'
      });
    }
    
    // Underscore.js
    if (window._ && _.VERSION && !_.forEach ||
        document.querySelector('script[src*="underscore"]')) {
      
      let version = window._ && _.VERSION ? _.VERSION : null;
      if (!version) {
        const underscoreVersionMatch = htmlContent.match(/underscore[.-]([\d.]+)/i);
        if (underscoreVersionMatch) version = underscoreVersionMatch[1];
      }
      
      technologies.push({
        name: 'Underscore.js',
        version: version,
        type: 'Utility',
        category: 'JavaScript Library'
      });
    }
    
    // Moment.js
    if (window.moment ||
        document.querySelector('script[src*="moment"]')) {
      
      let version = window.moment ? moment.version : null;
      if (!version) {
        const momentVersionMatch = htmlContent.match(/moment[.-]([\d.]+)/i);
        if (momentVersionMatch) version = momentVersionMatch[1];
      }
      
      technologies.push({
        name: 'Moment.js',
        version: version,
        type: 'Date',
        category: 'JavaScript Library'
      });
    }
    
    // D3.js
    if (window.d3 ||
        document.querySelector('script[src*="d3.js"], script[src*="d3.min.js"]')) {
      
      let version = window.d3 ? d3.version : null;
      if (!version) {
        const d3VersionMatch = htmlContent.match(/d3@([\d.]+)/i);
        if (d3VersionMatch) version = d3VersionMatch[1];
      }
      
      technologies.push({
        name: 'D3.js',
        version: version,
        type: 'Visualization',
        category: 'JavaScript Library'
      });
    }
    
    // Three.js
    if (window.THREE ||
        document.querySelector('script[src*="three.js"], script[src*="three.min.js"]')) {
      
      let version = window.THREE ? THREE.REVISION : null;
      if (!version) {
        const threeVersionMatch = htmlContent.match(/three@([\d.]+)/i);
        if (threeVersionMatch) version = threeVersionMatch[1];
      }
      
      technologies.push({
        name: 'Three.js',
        version: version,
        type: '3D',
        category: 'JavaScript Library'
      });
    }
    
    // Chart.js
    if (window.Chart ||
        document.querySelector('script[src*="chart.js"]')) {
      
      let version = window.Chart ? Chart.version : null;
      if (!version) {
        const chartVersionMatch = htmlContent.match(/chart\.js@([\d.]+)/i);
        if (chartVersionMatch) version = chartVersionMatch[1];
      }
      
      technologies.push({
        name: 'Chart.js',
        version: version,
        type: 'Visualization',
        category: 'JavaScript Library'
      });
    }
    
    // Socket.io
    if (window.io ||
        document.querySelector('script[src*="socket.io"]')) {
      
      let version = null;
      const socketVersionMatch = htmlContent.match(/socket\.io@([\d.]+)/i);
      if (socketVersionMatch) version = socketVersionMatch[1];
      
      technologies.push({
        name: 'Socket.io',
        version: version,
        type: 'Realtime',
        category: 'JavaScript Library'
      });
    }
    
    // Axios
    if (window.axios ||
        document.querySelector('script[src*="axios"]')) {
      
      let version = window.axios ? axios.VERSION : null;
      if (!version) {
        const axiosVersionMatch = htmlContent.match(/axios@([\d.]+)/i);
        if (axiosVersionMatch) version = axiosVersionMatch[1];
      }
      
      technologies.push({
        name: 'Axios',
        version: version,
        type: 'HTTP Client',
        category: 'JavaScript Library'
      });
    }
    
    // Redux
    if (window.Redux || window.__REDUX_DEVTOOLS_EXTENSION__ ||
        document.querySelector('script[src*="redux"]')) {
      
      let version = null;
      const reduxVersionMatch = htmlContent.match(/redux@([\d.]+)/i);
      if (reduxVersionMatch) version = reduxVersionMatch[1];
      
      technologies.push({
        name: 'Redux',
        version: version,
        type: 'State Management',
        category: 'JavaScript Library'
      });
    }
    
    // core-js
    if (window._babelPolyfill ||
        document.querySelector('script[src*="core-js"]') ||
        htmlContent.includes('core-js')) {
      
      let version = null;
      const coreVersionMatch = htmlContent.match(/core-js@([\d.]+)/i);
      if (coreVersionMatch) version = coreVersionMatch[1];
      
      technologies.push({
        name: 'core-js',
        version: version,
        type: 'Polyfill',
        category: 'JavaScript Library'
      });
    }
    
    // Goober
    if (htmlContent.includes('goober') ||
        document.querySelector('script[src*="goober"]')) {
      
      let version = null;
      const gooberVersionMatch = htmlContent.match(/goober@([\d.]+)/i);
      if (gooberVersionMatch) version = gooberVersionMatch[1];
      
      technologies.push({
        name: 'Goober',
        version: version,
        type: 'CSS-in-JS',
        category: 'JavaScript Library'
      });
    }
    
    // LottieFiles
    if (window.lottie ||
        document.querySelector('script[src*="lottie"]') ||
        document.querySelector('lottie-player')) {
      
      let version = null;
      const lottieVersionMatch = htmlContent.match(/lottie[-@]([\d.]+)/i);
      if (lottieVersionMatch) version = lottieVersionMatch[1];
      
      technologies.push({
        name: 'LottieFiles',
        version: version,
        type: 'Animation',
        category: 'JavaScript Library'
      });
    }
  }
  
  // --- RILEVAMENTO CSS FRAMEWORKS ---
  function detectCSSFrameworks() {
    const htmlContent = document.documentElement.outerHTML;
    
    // Bootstrap
    if (document.querySelector('link[href*="bootstrap"]') || 
        document.body.classList.contains('bootstrap') ||
        document.querySelectorAll('.row.col-md, .container-fluid').length > 0 ||
        document.querySelector('script[src*="bootstrap"]')) {
      
      let version = null;
      if (window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) {
        version = window.bootstrap.Tooltip.VERSION;
      } else {
        const bootstrapVersionMatch = htmlContent.match(/bootstrap[.-]?([\d.]+)/i);
        if (bootstrapVersionMatch) version = bootstrapVersionMatch[1];
      }
      
      technologies.push({
        name: 'Bootstrap',
        version: version,
        type: 'Framework',
        category: 'CSS Framework'
      });
    }
    
    // Tailwind CSS
    if (document.querySelector('link[href*="tailwind"]') || 
        document.querySelectorAll('[class*="text-"], [class*="bg-"], [class*="w-"]').length > 10 ||
        htmlContent.includes('tailwind')) {
      
      let version = null;
      const tailwindVersionMatch = htmlContent.match(/tailwindcss[.-]?([\d.]+)/i);
      if (tailwindVersionMatch) version = tailwindVersionMatch[1];
      
      technologies.push({
        name: 'Tailwind CSS',
        version: version,
        type: 'Utility-first',
        category: 'CSS Framework'
      });
    }
    
    // Bulma
    if (document.querySelector('link[href*="bulma"]') || 
        document.querySelectorAll('.column, .columns, .is-').length > 5 ||
        htmlContent.includes('bulma')) {
      
      let version = null;
      const bulmaVersionMatch = htmlContent.match(/bulma[.-]?([\d.]+)/i);
      if (bulmaVersionMatch) version = bulmaVersionMatch[1];
      
      technologies.push({
        name: 'Bulma',
        version: version,
        type: 'Framework',
        category: 'CSS Framework'
      });
    }
    
    // Foundation
    if (document.querySelector('link[href*="foundation"]') || 
        document.querySelectorAll('.row .columns, .reveal-modal').length > 0 ||
        htmlContent.includes('foundation')) {
      
      let version = null;
      const foundationVersionMatch = htmlContent.match(/foundation[.-]?([\d.]+)/i);
      if (foundationVersionMatch) version = foundationVersionMatch[1];
      
      technologies.push({
        name: 'Foundation',
        version: version,
        type: 'Framework',
        category: 'CSS Framework'
      });
    }
    
    // Material Design
    if (document.querySelector('link[href*="material"]') || 
        document.querySelectorAll('.mdl-layout, .mat-button, .md-chip').length > 0 ||
        htmlContent.includes('material-design') ||
        htmlContent.includes('materialize')) {
      
      let version = null;
      const materialVersionMatch = htmlContent.match(/material[.-]?([\d.]+)/i);
      if (materialVersionMatch) version = materialVersionMatch[1];
      
      technologies.push({
        name: 'Material Design',
        version: version,
        type: 'Design System',
        category: 'CSS Framework'
      });
    }
    
    // Semantic UI
    if (document.querySelector('link[href*="semantic-ui"]') || 
        document.querySelectorAll('.ui.segment, .ui.button, .ui.grid').length > 0 ||
        htmlContent.includes('semantic-ui')) {
      
      let version = null;
      const semanticVersionMatch = htmlContent.match(/semantic-ui[.-]?([\d.]+)/i);
      if (semanticVersionMatch) version = semanticVersionMatch[1];
      
      technologies.push({
        name: 'Semantic UI',
        version: version,
        type: 'Framework',
        category: 'CSS Framework'
      });
    }
  }
  
  // --- RILEVAMENTO DATABASE ---
  function detectDatabases() {
    const htmlContent = document.documentElement.outerHTML;
    
    // MySQL
    if (htmlContent.includes('mysql') || 
        htmlContent.includes('MySQL') || 
        document.querySelector('meta[name="generator"][content*="MySQL"]')) {
      
      let version = null;
      const mysqlVersionMatch = htmlContent.match(/MySQL\s+([\d.]+)/i);
      if (mysqlVersionMatch) version = mysqlVersionMatch[1];
      
      technologies.push({
        name: 'MySQL',
        version: version,
        type: 'Database',
        category: 'Database'
      });
    }
    
    // PostgreSQL
    if (htmlContent.includes('postgresql') || 
        htmlContent.includes('PostgreSQL') || 
        document.querySelector('meta[name="generator"][content*="PostgreSQL"]')) {
      
      let version = null;
      const pgVersionMatch = htmlContent.match(/PostgreSQL\s+([\d.]+)/i);
      if (pgVersionMatch) version = pgVersionMatch[1];
      
      technologies.push({
        name: 'PostgreSQL',
        version: version,
        type: 'Database',
        category: 'Database'
      });
    }
    
    // MongoDB
    if (htmlContent.includes('mongodb') || 
        htmlContent.includes('MongoDB') || 
        document.querySelector('meta[name="generator"][content*="MongoDB"]')) {
      
      let version = null;
      const mongoVersionMatch = htmlContent.match(/MongoDB\s+([\d.]+)/i);
      if (mongoVersionMatch) version = mongoVersionMatch[1];
      
      technologies.push({
        name: 'MongoDB',
        version: version,
        type: 'Database',
        category: 'Database'
      });
    }
    
    // SQLite
    if (htmlContent.includes('sqlite') || 
        htmlContent.includes('SQLite') || 
        document.querySelector('meta[name="generator"][content*="SQLite"]')) {
      
      let version = null;
      const sqliteVersionMatch = htmlContent.match(/SQLite\s+([\d.]+)/i);
      if (sqliteVersionMatch) version = sqliteVersionMatch[1];
      
      technologies.push({
        name: 'SQLite',
        version: version,
        type: 'Database',
        category: 'Database'
      });
    }
    
    // Oracle Database
    if (htmlContent.includes('oracle database') || 
        htmlContent.includes('Oracle Database') || 
        document.querySelector('meta[name="generator"][content*="Oracle"]')) {
      
      let version = null;
      const oracleVersionMatch = htmlContent.match(/Oracle\s+([\d.]+)/i);
      if (oracleVersionMatch) version = oracleVersionMatch[1];
      
      technologies.push({
        name: 'Oracle Database',
        version: version,
        type: 'Database',
        category: 'Database'
      });
    }
    
    // Microsoft SQL Server
    if (htmlContent.includes('sql server') || 
        htmlContent.includes('SQL Server') || 
        document.querySelector('meta[name="generator"][content*="SQL Server"]')) {
      
      let version = null;
      const mssqlVersionMatch = htmlContent.match(/SQL\s+Server\s+([\d.]+)/i);
      if (mssqlVersionMatch) version = mssqlVersionMatch[1];
      
      technologies.push({
        name: 'Microsoft SQL Server',
        version: version,
        type: 'Database',
        category: 'Database'
      });
    }
    
    // Redis
    if (htmlContent.includes('redis') || 
        htmlContent.includes('Redis') || 
        document.querySelector('meta[name="generator"][content*="Redis"]')) {
      
      let version = null;
      const redisVersionMatch = htmlContent.match(/Redis\s+([\d.]+)/i);
      if (redisVersionMatch) version = redisVersionMatch[1];
      
      technologies.push({
        name: 'Redis',
        version: version,
        type: 'Cache Database',
        category: 'Database'
      });
    }
    
    // Firebase
    if (document.querySelector('script[src*="firebase"]') ||
        htmlContent.includes('firebase') ||
        window.firebase) {
      
      let version = null;
      const firebaseVersionMatch = htmlContent.match(/firebase\/([\d.]+)/i);
      if (firebaseVersionMatch) version = firebaseVersionMatch[1];
      
      technologies.push({
        name: 'Firebase',
        version: version,
        type: 'Database',
        category: 'Database'
      });
    }
  }
  
  // --- RILEVAMENTO LINGUAGGI DI PROGRAMMAZIONE ---
  function detectProgrammingLanguages() {
    const htmlContent = document.documentElement.outerHTML;
    
    // PHP (già parzialmente coperto in altri rilevamenti)
    if (document.querySelector('meta[http-equiv="X-Powered-By"][content*="PHP"]') ||
        htmlContent.includes('php') ||
        document.cookie.includes('PHPSESSID')) {
      
      let version = null;
      const phpVersionMatch = htmlContent.match(/PHP\/([\d.]+)/i);
      if (phpVersionMatch) version = phpVersionMatch[1];
      
      technologies.push({
        name: 'PHP',
        version: version,
        type: 'Linguaggio',
        category: 'Linguaggio di programmazione'
      });
      
      // Laravel
      if (document.querySelector('input[name="_token"], meta[name="csrf-token"]') &&
          document.cookie.includes('laravel_session') ||
          htmlContent.includes('Laravel')) {
        
        let version = null;
        const laravelVersionMatch = htmlContent.match(/Laravel\s+([\d.]+)/i);
        if (laravelVersionMatch) version = laravelVersionMatch[1];
        
        technologies.push({
          name: 'Laravel',
          version: version,
          type: 'Framework',
          category: 'PHP'
        });
      }
      
      // Symfony
      if (document.querySelector('div.sf-toolbar, #sfwdt, div[class*="sf-"]') ||
          document.querySelector('meta[name="generator"][content*="Symfony"]') ||
          htmlContent.includes('symfony')) {
        
        let version = null;
        const symfonyVersionMatch = htmlContent.match(/Symfony\s+([\d.]+)/i);
        if (symfonyVersionMatch) version = symfonyVersionMatch[1];
        
        technologies.push({
          name: 'Symfony',
          version: version,
          type: 'Framework',
          category: 'PHP'
        });
      }
      
      // CodeIgniter
      if (document.querySelector('meta[name="generator"][content*="CodeIgniter"]') ||
          document.querySelector('input[name="csrf_test_name"]') ||
          htmlContent.includes('codeigniter')) {
        
        let version = null;
        const ciVersionMatch = htmlContent.match(/CodeIgniter\s+([\d.]+)/i);
        if (ciVersionMatch) version = ciVersionMatch[1];
        
        technologies.push({
          name: 'CodeIgniter',
          version: version,
          type: 'Framework',
          category: 'PHP'
        });
      }
    }
    
    // Ruby
    if (document.querySelector('meta[name="csrf-param"][content="authenticity_token"]') ||
        htmlContent.includes('ruby') ||
        htmlContent.includes('Rails') ||
        document.cookie.includes('_rails_session')) {
      
      technologies.push({
        name: 'Ruby',
        type: 'Linguaggio',
        category: 'Linguaggio di programmazione'
      });
      
      // Ruby on Rails
      if (document.querySelector('meta[name="csrf-param"][content="authenticity_token"]') ||
          htmlContent.includes('rails') ||
          document.cookie.includes('_rails_session')) {
        
        let version = null;
        const railsVersionMatch = htmlContent.match(/Rails\s+([\d.]+)/i);
        if (railsVersionMatch) version = railsVersionMatch[1];
        
        technologies.push({
          name: 'Ruby on Rails',
          version: version,
          type: 'Framework',
          category: 'Framework Web'
        });
      }
    }
    
    // Python
    if (htmlContent.includes('django') ||
        htmlContent.includes('flask') ||
        htmlContent.includes('python') ||
        document.cookie.includes('django_') ||
        document.querySelector('meta[name="generator"][content*="Django"]')) {
      
      technologies.push({
        name: 'Python',
        type: 'Linguaggio',
        category: 'Linguaggio di programmazione'
      });
      
      // Django
      if (htmlContent.includes('django') ||
          document.cookie.includes('django_') ||
          document.querySelector('meta[name="generator"][content*="Django"]')) {
        
        let version = null;
        const djangoVersionMatch = htmlContent.match(/Django\s+([\d.]+)/i);
        if (djangoVersionMatch) version = djangoVersionMatch[1];
        
        technologies.push({
          name: 'Django',
          version: version,
          type: 'Framework',
          category: 'Framework Web'
        });
      }
      
      // Flask
      if (htmlContent.includes('flask') ||
          document.cookie.includes('session') && htmlContent.includes('python')) {
        technologies.push({
          name: 'Flask',
          type: 'Framework',
          category: 'Framework Web'
        });
      }
    }
    
    // Node.js (backend, ma rilevabile da alcuni pattern)
    if (htmlContent.includes('node.js') ||
        htmlContent.includes('nodejs') ||
        document.querySelector('script[src*="node_modules"]')) {
      
      technologies.push({
        name: 'Node.js',
        type: 'Runtime',
        category: 'Linguaggio di programmazione'
      });
      
      // Express.js
      if (htmlContent.includes('express') ||
          htmlContent.includes('req.query') ||
          document.cookie.includes('connect.sid')) {
        technologies.push({
          name: 'Express.js',
          type: 'Framework',
          category: 'Framework Web'
        });
      }
    }
  }
  
  // --- RILEVAMENTO PWA & SECURITY ---
  function detectPWAAndSecurity() {
    const htmlContent = document.documentElement.outerHTML;
    
    // Progressive Web App
    if (document.querySelector('link[rel="manifest"]') ||
        document.querySelector('meta[name="apple-mobile-web-app-capable"]') ||
        document.querySelector('script[src*="service-worker.js"]') ||
        navigator.serviceWorker) {
      technologies.push({
        name: 'PWA',
        type: 'Progressive Web App',
        category: 'PWA'
      });
    }
    
    // HSTS (HTTP Strict Transport Security)
    if (document.querySelector('meta[http-equiv="Strict-Transport-Security"]') ||
        htmlContent.includes('Strict-Transport-Security')) {
      technologies.push({
        name: 'HSTS',
        type: 'Security Policy',
        category: 'Security'
      });
    }
    
    // CSP (Content Security Policy)
    if (document.querySelector('meta[http-equiv="Content-Security-Policy"]') ||
        htmlContent.includes('Content-Security-Policy')) {
      technologies.push({
        name: 'CSP',
        type: 'Security Policy',
        category: 'Security'
      });
    }
    
    // CORS (Cross-Origin Resource Sharing)
    if (document.querySelector('meta[http-equiv="Access-Control-Allow-Origin"]') ||
        htmlContent.includes('Access-Control-Allow')) {
      technologies.push({
        name: 'CORS',
        type: 'Security Policy',
        category: 'Security'
      });
    }
  }
  
  // --- RILEVAMENTO STATIC SITE GENERATORS ---
  function detectStaticSiteGenerators() {
    const htmlContent = document.documentElement.outerHTML;
    
    // Jekyll
    if (document.querySelector('meta[name="generator"][content*="Jekyll"]') ||
        htmlContent.includes('jekyll')) {
      
      let version = null;
      const jekyllVersionMatch = htmlContent.match(/jekyll\s+v?([\d.]+)/i);
      if (jekyllVersionMatch) version = jekyllVersionMatch[1];
      
      technologies.push({
        name: 'Jekyll',
        version: version,
        type: 'Static Generator',
        category: 'Static Site Generator'
      });
    }
    
    // Hugo
    if (document.querySelector('meta[name="generator"][content*="Hugo"]') ||
        htmlContent.includes('hugo-')) {
      
      let version = null;
      const hugoVersionMatch = htmlContent.match(/hugo\s+v?([\d.]+)/i);
      if (hugoVersionMatch) version = hugoVersionMatch[1];
      
      technologies.push({
        name: 'Hugo',
        version: version,
        type: 'Static Generator',
        category: 'Static Site Generator'
      });
    }
    
    // Gatsby (già rilevato nei framework JS, ma aggiungiamo anche qui)
    if (window.___gatsby || 
        document.getElementById('___gatsby') ||
        document.querySelector('meta[name="generator"][content*="Gatsby"]') ||
        htmlContent.includes('gatsby-')) {
      
      let version = null;
      const gatsbyVersionMatch = htmlContent.match(/gatsby@([\d.]+)/i);
      if (gatsbyVersionMatch) version = gatsbyVersionMatch[1];
      
      technologies.push({
        name: 'Gatsby',
        version: version,
        type: 'Static Generator',
        category: 'Static Site Generator'
      });
    }
    
    // Next.js (già rilevato nei framework JS, ma aggiungiamo anche qui)
    if (document.getElementById('__next') || 
        document.querySelector('script[data-next-page]') ||
        htmlContent.includes('__NEXT_DATA__')) {
      
      let version = null;
      const nextVersionMatch = htmlContent.match(/next\/static\/([\d.]+)/i);
      if (nextVersionMatch) version = nextVersionMatch[1];
      
      technologies.push({
        name: 'Next.js',
        version: version,
        type: 'Static Generator',
        category: 'Static Site Generator'
      });
    }
  }
  
  // --- RILEVAMENTO PIATTAFORME (PAAS) ---
  function detectPlatforms() {
    const htmlContent = document.documentElement.outerHTML;
    
    // GitHub Pages
    if (document.querySelector('meta[name="generator"][content*="GitHub"]') ||
        htmlContent.includes('github-pages') ||
        location.hostname.includes('github.io')) {
      technologies.push({
        name: 'GitHub Pages',
        type: 'Hosting',
        category: 'PaaS'
      });
    }
    
    // AWS (Amazon Web Services)
    if (document.querySelector('script[src*="amazonaws.com"]') ||
        htmlContent.includes('amazonaws.com') ||
        htmlContent.includes('aws-') ||
        document.cookie.includes('aws')) {
      technologies.push({
        name: 'Amazon Web Services',
        type: 'Cloud Platform',
        category: 'PaaS'
      });
    }
    
    // Netlify
    if (document.querySelector('meta[name="generator"][content*="Netlify"]') ||
        htmlContent.includes('netlify') ||
        location.hostname.includes('netlify.app')) {
      technologies.push({
        name: 'Netlify',
        type: 'Hosting',
        category: 'PaaS'
      });
    }
    
    // Vercel
    if (document.querySelector('meta[name="generator"][content*="Vercel"]') ||
        htmlContent.includes('vercel') ||
        location.hostname.includes('vercel.app')) {
      technologies.push({
        name: 'Vercel',
        type: 'Hosting',
        category: 'PaaS'
      });
    }
    
    // Heroku
    if (location.hostname.includes('herokuapp.com') ||
        htmlContent.includes('heroku')) {
      technologies.push({
        name: 'Heroku',
        type: 'Cloud Platform',
        category: 'PaaS'
      });
    }
    
    // Firebase Hosting
    if (location.hostname.includes('firebaseapp.com') ||
        location.hostname.includes('web.app') ||
        htmlContent.includes('firebase-hosting')) {
      technologies.push({
        name: 'Firebase Hosting',
        type: 'Hosting',
        category: 'PaaS'
      });
    }
  }
  
  // --- RILEVAMENTO ANALYTICS & MARKETING ---
  function detectAnalyticsAndMarketing() {
    const htmlContent = document.documentElement.outerHTML;
    
    // Google Analytics
    if (window.ga || window.gtag || window.dataLayer || 
        document.querySelector('script[src*="google-analytics.com"], script[src*="googletagmanager.com"]') ||
        htmlContent.includes('google-analytics') ||
        htmlContent.includes('googletagmanager')) {
      
      // Distinguiamo tra UA e GA4
      if (htmlContent.includes('UA-')) {
        technologies.push({
          name: 'Google Analytics (Universal)',
          type: 'Web Analytics',
          category: 'Analytics'
        });
      } else if (htmlContent.includes('G-')) {
        technologies.push({
          name: 'Google Analytics 4',
          type: 'Web Analytics',
          category: 'Analytics'
        });
      } else {
        technologies.push({
          name: 'Google Analytics',
          type: 'Web Analytics',
          category: 'Analytics'
        });
      }
    }
    
    // Adobe Analytics
    if (window.s && window.s.version || 
        window.AppMeasurement ||
        document.querySelector('script[src*="analytics.sitecatalyst"]') ||
        htmlContent.includes('adobe analytics') ||
        htmlContent.includes('omniture')) {
      
      let version = window.s && window.s.version ? window.s.version : null;
      
      technologies.push({
        name: 'Adobe Analytics',
        version: version,
        type: 'Web Analytics',
        category: 'Analytics'
      });
    }
    
    // Adobe Experience Platform
    if (htmlContent.includes('adobe experience platform') ||
        htmlContent.includes('adobe identity service') ||
        document.querySelector('script[src*="demdex.net"]')) {
      technologies.push({
        name: 'Adobe Experience Platform Identity Service',
        type: 'Customer Data Platform',
        category: 'Customer data platform'
      });
    }
    
    // Google Tag Manager
    if (window.dataLayer || 
        document.querySelector('script[src*="googletagmanager.com/gtm.js"]') ||
        htmlContent.includes('gtm.js') ||
        htmlContent.includes('GTM-')) {
      technologies.push({
        name: 'Google Tag Manager',
        type: 'Tag Management',
        category: 'Tag Manager'
      });
    }
    
    // Facebook Pixel
    if (window.fbq || 
        document.querySelector('script[src*="connect.facebook.net"]') ||
        htmlContent.includes('fbq(')) {
      technologies.push({
        name: 'Facebook Pixel',
        type: 'Marketing',
        category: 'Marketing'
      });
    }
    
    // HubSpot
    if (window._hsq || 
        document.querySelector('script[src*="js.hs-scripts.com"]') ||
        htmlContent.includes('hubspot')) {
      technologies.push({
        name: 'HubSpot',
        type: 'Marketing',
        category: 'Marketing'
      });
    }
    
    // New Relic
    if (window.newrelic ||
        document.querySelector('script[src*="newrelic"]') ||
        htmlContent.includes('newrelic')) {
      technologies.push({
        name: 'New Relic',
        type: 'Performance Monitoring',
        category: 'RUM'
      });
    }
    
    // Optimizely
    if (window.optimizely || 
        document.querySelector('script[src*="optimizely.com"]') ||
        htmlContent.includes('optimizely')) {
      technologies.push({
        name: 'Optimizely',
        type: 'A/B Testing',
        category: 'Marketing'
      });
    }
    
    // Cxense
    if (htmlContent.includes('cxense') ||
        document.querySelector('script[src*="cxense"]')) {
      technologies.push({
        name: 'Cxense',
        type: 'DMP',
        category: 'Personalisation'
      });
      
      technologies.push({
        name: 'Cxense',
        type: 'Customer Segmentation',
        category: 'Segmentation'
      });
    }
    
    // Advertising Networks
    // Google AdSense
    if (window.adsbygoogle ||
        document.querySelector('script[src*="pagead2.googlesyndication.com"]') ||
        htmlContent.includes('adsbygoogle')) {
      technologies.push({
        name: 'Google AdSense',
        type: 'Ad Network',
        category: 'Network Pubblicitario'
      });
    }
    
    // Google Publisher Tag
    if (window.googletag ||
        document.querySelector('script[src*="googletagservices.com"]') ||
        htmlContent.includes('googletag')) {
      technologies.push({
        name: 'Google Publisher Tag',
        type: 'Ad Network',
        category: 'Network Pubblicitario'
      });
    }
    
    // DoubleClick
    if (window.googletag ||
        document.querySelector('script[src*="doubleclick.net"]') ||
        htmlContent.includes('doubleclick')) {
      technologies.push({
        name: 'DoubleClick Campaign Manager (DCM)',
        type: 'Ad Network',
        category: 'Network Pubblicitario'
      });
    }
    
    // Amazon Advertising
    if (document.querySelector('script[src*="amazon-adsystem"]') ||
        htmlContent.includes('amazon-adsystem')) {
      technologies.push({
        name: 'Amazon Advertising',
        type: 'Ad Network',
        category: 'Network Pubblicitario'
      });
    }
    
    // Prebid
    if (window.pbjs ||
        document.querySelector('script[src*="prebid"]') ||
        htmlContent.includes('prebid')) {
      
      let version = null;
      const prebidVersionMatch = htmlContent.match(/prebid[.-]([\d.]+)/i);
      if (prebidVersionMatch) version = prebidVersionMatch[1];
      
      technologies.push({
        name: 'Prebid',
        version: version,
        type: 'Header Bidding',
        category: 'Network Pubblicitario'
      });
    }
    
    // Integral Ad Science
    if (document.querySelector('script[src*="adsafeprotected"]') ||
        htmlContent.includes('ias') ||
        htmlContent.includes('integralads')) {
      technologies.push({
        name: 'Integral Ad Science',
        type: 'Ad Verification',
        category: 'Network Pubblicitario'
      });
    }
    
    // Ad Lightning
    if (document.querySelector('script[src*="adlightning"]') ||
        htmlContent.includes('adlightning')) {
      technologies.push({
        name: 'Ad Lightning',
        type: 'Ad Quality',
        category: 'Network Pubblicitario'
      });
    }
  }
  
  // --- RILEVAMENTO ALTRE TECNOLOGIE ---
  function detectMiscTechnologies() {
    const htmlContent = document.documentElement.outerHTML;
    
    // Font Awesome
    if (document.querySelector('link[href*="fontawesome"]') || 
        document.querySelector('i.fa, i.fas, i.far, i.fab') ||
        htmlContent.includes('fontawesome')) {
      
      let version = null;
      const faVersionMatch = htmlContent.match(/fontawesome\/([\d.]+)/i);
      if (faVersionMatch) version = faVersionMatch[1];
      
      technologies.push({
        name: 'Font Awesome',
        version: version,
        type: 'Icone',
        category: 'Font'
      });
    }
    
    // Google Fonts
    if (document.querySelector('link[href*="fonts.googleapis.com"]') ||
        htmlContent.includes('fonts.googleapis.com')) {
      technologies.push({
        name: 'Google Fonts',
        type: 'Font',
        category: 'Font'
      });
    }
    
    // Open Graph
    if (document.querySelector('meta[property^="og:"]') ||
        htmlContent.includes('og:')) {
      technologies.push({
        name: 'Open Graph',
        type: 'Meta Protocol',
        category: 'Miscellanea'
      });
    }
    
    // ServiceNow
    if (htmlContent.includes('servicenow') ||
        document.querySelector('script[src*="servicenow"]')) {
      technologies.push({
        name: 'ServiceNow',
        type: 'Platform',
        category: 'Miscellanea'
      });
    }
    
    // Webpack
    if (window.webpackJsonp ||
        window.__webpack_require__ ||
        htmlContent.includes('webpack') ||
        document.querySelector('script[src*="bundle.js"]')) {
      
      let version = null;
      const webpackVersionMatch = htmlContent.match(/webpack\/([\d.]+)/i);
      if (webpackVersionMatch) version = webpackVersionMatch[1];
      
      technologies.push({
        name: 'Webpack',
        type: 'Bundler',
        category: 'Miscellanea'
      });
    }
  }
  
  // Esecuzione dei rilevamenti
  detectWebServer();
  detectCacheTools();
  detectCDN();
  detectCMS();
  detectJSFrameworks();
  detectJSLibraries();
  detectProgrammingLanguages();
  detectDatabases();
  detectCSSFrameworks();
  detectAnalyticsAndMarketing();
  detectPWAAndSecurity();
  detectStaticSiteGenerators();
  detectPlatforms();
  detectMiscTechnologies();
  
  // Controlla gli script per trovare altre tecnologie
  const scripts = document.querySelectorAll('script');
  scripts.forEach(script => {
    const src = script.getAttribute('src') || '';
    const scriptContent = script.textContent || '';
    
    // Librerie specifiche dallo src
    if (src.includes('jquery.min.js') || src.includes('jquery.js'))
      addIfNotExists('jQuery', 'JavaScript Library');
    if (src.includes('react.min.js') || src.includes('react.js'))
      addIfNotExists('React', 'JavaScript Framework');
    if (src.includes('vue.min.js') || src.includes('vue.js'))
      addIfNotExists('Vue.js', 'JavaScript Framework');
    if (src.includes('angular.min.js') || src.includes('angular.js'))
      addIfNotExists('Angular', 'JavaScript Framework');
    if (src.includes('lodash.min.js') || src.includes('lodash.js'))
      addIfNotExists('Lodash', 'JavaScript Library');
    if (src.includes('axios.min.js') || src.includes('axios.js'))
      addIfNotExists('Axios', 'JavaScript Library');
    if (src.includes('bootstrap.min.js') || src.includes('bootstrap.js'))
      addIfNotExists('Bootstrap', 'CSS Framework');
    if (src.includes('gsap.min.js') || src.includes('TweenMax'))
      addIfNotExists('GSAP', 'Animation');
    if (src.includes('firebase'))
      addIfNotExists('Firebase', 'Database');
    if (src.includes('emotion'))
      addIfNotExists('Emotion', 'CSS-in-JS');
    if (src.includes('lottie'))
      addIfNotExists('LottieFiles', 'Animation');
    if (src.includes('next'))
      addIfNotExists('Next.js', 'Framework');
  });
  
  // Funzione helper per aggiungere tecnologie solo se non esistono già
  function addIfNotExists(name, type) {
    const exists = technologies.some(tech => tech.name === name);
    if (!exists) {
      technologies.push({
        name: name,
        type: type,
        category: getCategoryForType(type)
      });
    }
  }
  
  // Funzione per determinare la categoria in base al tipo
  function getCategoryForType(type) {
    const typeToCategory = {
      'Framework': 'JavaScript Framework',
      'Library': 'JavaScript Library',
      'JavaScript Library': 'JavaScript Library',
      'JavaScript Framework': 'JavaScript Framework',
      'Animation': 'JavaScript Library',
      'CSS Framework': 'CSS Framework',
      'CSS-in-JS': 'JavaScript Library',
      'Database': 'Database',
      'Web Server': 'Web Server',
      'E-commerce': 'E-commerce',
      'CMS': 'CMS'
    };
    
    return typeToCategory[type] || 'Miscellanea';
  }
  
  // Deduplica le tecnologie trovate
  const uniqueTechnologies = [];
  const techNames = new Set();
  
  technologies.forEach(tech => {
    if (!techNames.has(tech.name)) {
      techNames.add(tech.name);
      uniqueTechnologies.push(tech);
    }
  });
  
  return uniqueTechnologies;
}