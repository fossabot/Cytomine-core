import Vue from 'vue'
import ImagePanel from './ImagePanel.vue'

function initBrowseImages() {
  if (document.getElementById('maps')) {
    new Vue({
      el: '#maps',
      render: h => h(ImagePanel)
    })
  } else {
    setTimeout(initBrowseImages, 15);
  }
}

initBrowseImages();