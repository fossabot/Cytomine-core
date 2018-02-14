
<template>
  <div>
    <button v-if="maps.length < maxMapsToShow" @click="addMap">Add a map</button>
    <p v-else>You can only have {{maxMapsToShow}} maps displayed</p>
    <div class="container">
      <ImagePanel v-for="map in maps" :key="map.id" @dragged="setMap" @mapIsLinked="linkMaps" @deleteMap="deleteMap" :mapView="mapView" :maps='maps' :currentMap="map" :lastEventMapId="lastEventMapId"></ImagePanel>
    </div>
  </div>
</template>

<script>
import ImagePanel from './components/ImagePanel'
import uuid from 'uuid'
import findIndex from 'lodash.findindex'

export default {
  name: 'ImagesBrowser',
  components: {
    ImagePanel,
  },
  data() {
    return {
      mapView: {
        mapCenter: [37.41, 8.82],
        mapZoom: 3,
        mapRotation: 0,
      },
      maxMapsToShow: 4,
      maps: [],
      lastEventMapId: null,
    }
  },
  methods: {
    setMap(payload) {
      this.mapView = {
        mapCenter: payload.view.getCenter(),
        mapZoom: payload.view.getZoom(),
        mapRotation: payload.view.getRotation(),
      }
      this.lastEventMapId = payload.mapId;
    },
    linkMaps(payload) {
      // Removes last linked map
      let index = findIndex(this.maps, (map) => {
        return map.linkedTo === payload[0];
      })
      if(index !== -1) {
        this.maps[index].linkedTo = "";
      }
      // Finds map index
      index = findIndex(this.maps, (map) => {
        return map.id === payload[0];
      })
      // Links maps
      this.maps[index].linkedTo = payload[1];
      index = findIndex(this.maps, (map) => {
        return map.id === payload[1];
      })
      this.maps[index].linkedTo = payload[0];
    },
    addMap() {
      if(this.maps.length < this.maxMapsToShow) {
        let id = uuid();
        this.maps.push({id: id, linkedTo: ""});
      }
    },
    deleteMap(payload) {
      let index = findIndex(this.maps, (map) => {
        return map.id === payload;
      })
      this.maps.splice(index, 1);
    }
  },
  created() {
    let id = uuid();
    this.maps.push({id: id, linkedTo: ""});
  },
}
</script>