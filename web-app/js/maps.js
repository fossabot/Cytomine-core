import Vue from 'vue'
import Map from './Map.vue'

function initMaps() {
  if (document.getElementById('maps')) {
    new Vue({
      el: '#maps',
      render: h => h(Map)
    })
  } else {
    setTimeout(initMaps, 15);
  }
}

initMaps();