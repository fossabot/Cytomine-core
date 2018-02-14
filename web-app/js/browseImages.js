import Vue from 'vue'
import ImagesBrowser from './ImagesBrowser.vue'

import VueOpenLayers from 'vuejs-openlayers'

Vue.use(VueOpenLayers);

function initImagesBrowser() {
  if (document.getElementById('maps')) {
    new Vue({
      el: '#maps',
      render: h => h(ImagesBrowser)
    })
  } else {
    setTimeout(initImagesBrowser, 15);
  }
}

initImagesBrowser();