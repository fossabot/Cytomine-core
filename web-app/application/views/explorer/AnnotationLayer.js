/*
 * Copyright (c) 2009-2017. Authors: see NOTICE file.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var AnnotationStatus = {
    NO_TERM: 'NO_TERM',
    MULTIPLE_TERM: 'MULTIPLE_TERM',
    TOO_SMALL: 'TOO_SMALL',
    REVIEW: 'REVIEW'
}
var AnnotationLayerUtils = AnnotationLayerUtils || {};
AnnotationLayerUtils.createFeatureFromAnnotation = function (annotation) {

    var location = annotation.location || annotation.get('location');
    var count = annotation.count ? annotation.count : "";
    var ratio = annotation.ratio ? annotation.ratio : undefined
    var terms = annotation.term || annotation.get('term');
    var format = new ol.format.WKT();
    var point = format.read(location);
    var geom = point.geometry;
    var feature = new ol.Feature({geometry: geom});


    if(window.app.status.currentProjectModel.get('blindMode')) {
        //if its in blind mode, show only term added by the current user
        var userByTerm = annotation.userByTerm || annotation.get('userByTerm');
        if(userByTerm) {
            var currentUserId = window.app.status.user.id;
            terms = _.pluck(_.filter(userByTerm, function(item){ return _.contains(item.user, currentUserId) }),'term');
        }
    }


    //no term associated
    var term = AnnotationStatus.NO_TERM;

    //multiple term
    if (terms.length==1 && terms[0]==0) {
        term = AnnotationStatus.NO_TERM;
    //multiple term
    } else if (terms.length > 1) {
        term = AnnotationStatus.MULTIPLE_TERM;
    } else if (terms.length == 1) {
        //put ID
        term = terms[0];
    }
    feature.attributes = {
        idAnnotation: annotation.id,
        measure: 'NO',
        listener: 'NO',
        importance: 10,
        term: term,
        count: count,
        opacity : ratio
    };
    return feature;
};

/* Annotation Layer */
OpenLayers.Format.Cytomine = OpenLayers.Class(OpenLayers.Format, {
    read: function (collection) {
        var self = this;

        var features = [];
        var nestedCollection = collection.collection;
        var termsToShow = this.annotationLayer.browseImageView.ontologyPanel.ontologyTreeView.getTermToShow();
        //just for perf
        var isTermRestriction = this.annotationLayer.browseImageView.ontologyPanel.ontologyTreeView.isTermRestriction();
        _.each(nestedCollection, function (annotation) {

            if(!annotation.term) {
                annotation.term = [];
            }

            var terms = annotation.term || annotation.get('term');
            if(terms.length==0){
                terms.push(0) // 0 = no term
            }

            if(isTermRestriction) {
                if(_.intersection(termsToShow,terms).length==0) {
                    return
                }
            }

            if (_.indexOf(self.annotationLayer.featuresHidden, annotation.id) != -1) {
                return;
            }
            var feature = AnnotationLayerUtils.createFeatureFromAnnotation(annotation);
            features.push(feature);
        });
        return features;
    }

});

var AnnotationLayer = function (user,name, imageID, userID, color, ontologyTreeView, browseImageView, map, reviewMode) {
    var self = this;
    this.user = user;
    this.ontologyTreeView = ontologyTreeView;
    this.pointRadius = window.localStorage.getItem("point_radius" + window.app.status.currentProject) || 8;
    if(window.app.view.isMobile) {this.pointRadius +=4;}
    this.name = name;
    this.map = map;
    this.imageID = imageID;
    this.userID = userID;
    this.reviewLayer = (name == "REVIEW") || (name == "Review layer");
    var roi  = (userID == "ROI");
    this.reviewMode = reviewMode;
    this.drawable = false;
    var rules = [new OpenLayers.Rule({
        symbolizer: {strokeColor: "#0000ff", strokeWidth: 2},
        // symbolizer: {}, // instead if you want to keep default colors
        elseFilter: true
    })];
    var selectedRules = [new OpenLayers.Rule({
        symbolizer: {strokeColor: "#00ff00", strokeWidth: 2}, //graphicZIndex:10000000
        // symbolizer: {}, // instead if you want to keep default colors
        elseFilter: true
    })];

    // get a copy of the default style
    var style = $.extend(true, {}, OpenLayers.Feature.Vector.style['default']);
    style.label = "${getLabel}";
    style.fillOpacity = "${getOpacity}";
    style.strokeOpacity = "${getOpacityBorder}";
    style.strokeWidth = 1 ;
    style.fillColor = '#EEEEEE';
    style.strokeColor= '${getStrokeColor}';
    style.strokeWidth= 1;
    style.pointRadius= this.pointRadius;
    style.graphicZIndex = 999;


    var defaultStyle = new OpenLayers.Style(style, {
                context: {
                    getLabel: function (feature) {
                        if (feature.geometry && feature.geometry.CLASS_NAME == "OpenLayers.Geometry.Polygon") {
                            var count = feature.attributes.count
                            if(count==undefined) {count = "";}
                            return count;
                        } else {
                            return "";
                        }
                    } ,
                    getOpacity: function (feature) {
                        return self.browseImageView.getOpacity();
                    },
                    getOpacityBorder: function (feature) {
                        return self.browseImageView.getOpacityBorder();
                    },
                    getStrokeColor: function (feature) {
                        var opacity = feature.attributes.opacity
                        if(opacity==undefined) {return '#000000';}
                        else if(opacity<0.33) {return "#B94A48"}
                        else if(opacity<0.66) {return "#C09853"}
                        //return "#468847"
                        return "#ff0000"
                    }
                }
            })
    defaultStyle.addRules(rules);


    var selectStyle = null;

    selectStyle = new OpenLayers.Style({
        'fillColor': '#EEEEEE',
        'fillOpacity': .8,
        'strokeColor': '#00FF00',
        'strokeWidth': 3,
        'pointRadius': this.pointRadius,
        graphicZIndex : 14
    });

    selectStyle.addRules(selectedRules);






    var styleMap = new OpenLayers.StyleMap({
        "default": defaultStyle,
        "select" : selectStyle
    });

    if (this.reviewLayer) {
        //review layer: paint it green
        styleMap.styles["default"].addRules(rules);
        styleMap.addUniqueValueRules('default', 'term', this.getSymbolizerReview(false));
        styleMap.styles["select"].addRules(rules);
        styleMap.addUniqueValueRules('select', 'term', this.getSymbolizerReview(true));
    } else if(userID == "ROI") {
        styleMap.styles["default"].addRules(rules);
        styleMap.addUniqueValueRules('default', 'term', this.getSymbolizerRoi(false));
        styleMap.styles["select"].addRules(rules);
        styleMap.addUniqueValueRules('select', 'term', this.getSymbolizerRoi(true));
    } else if (!reviewMode) {
        styleMap.styles["default"].addRules(rules);
        styleMap.addUniqueValueRules('default', 'term', this.getSymbolizer(false));
        styleMap.styles["select"].addRules(selectedRules);
        styleMap.addUniqueValueRules('select', 'term', this.getSymbolizer(true));
    } else {
        //a layer in review mode but not a review layer: paint it red
        styleMap.styles["default"].addRules(rules);
        styleMap.addUniqueValueRules('default', 'term', this.getSymbolizerReviewNotReviewLayer(false));
        styleMap.styles["select"].addRules(rules);
        styleMap.addUniqueValueRules('select', 'term', this.getSymbolizerReviewNotReviewLayer(true));
    }

    var annotationsCollection = new AnnotationCollection({user: this.userID, image: this.imageID, roi:roi,notReviewedOnly: reviewMode,reviewed:this.reviewLayer,showWKT: true,showTerm: true, kmeans:true}).url().replace("json", "jsonp");





    this.vectorsLayer = new OpenLayers.Layer.Vector(this.name, {
        rendererOptions: { zIndexing: true },
        //renderers: ["Canvas", "SVG", "VML"],
        strategies: [
            new OpenLayers.Strategy.BBOX({resFactor: 1,ratio: 2})
        ],
        protocol: new OpenLayers.Protocol.Script({
            url: annotationsCollection,
            format: new OpenLayers.Format.Cytomine({ annotationLayer: this}),
            callbackKey: "callback"
        }) ,
        'styleMap': styleMap

    });
    this.vectorsLayer.strategies[0].activate();


    this.controls = null;
    this.dialog = null;
    this.rotate = false;
    this.fill = false;
    this.featuresHidden = [];
    this.resize = false;
    this.drag = false;
    this.irregular = false;
    this.aspectRatio = false;
    this.browseImageView = browseImageView;
    this.map = browseImageView.map;
    this.popup = null;
    this.hoverControl = null;
    this.triggerUpdateOnUnselect = true;
    this.isOwner = null;
    this.deleteOnSelect = false; //true if select tool checked
    this.measureOnSelect = false;
    this.magicOnClick = false;
    this.cpt = 0;
}

AnnotationLayer.prototype = {
    defaultStrokeColor: "#000000",
    selectedStrokeColor: "#0000ff",
    getSymbolizer: function (selected) {

        var strokeColor = this.defaultStrokeColor;
        if (selected) {
            strokeColor = this.selectedStrokeColor;
        }
        var symbolizers_lookup = {};
        var self = this;
        //NO TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.NO_TERM] = {
            'fillColor': "#EEEEEE",
            'strokeWidth': 3,
            'pointRadius': this.pointRadius,
            "strokeColor": strokeColor
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.MULTIPLE_TERM] = {
            'fillColor': "#CCCCCC",
            'strokeWidth': 3,
            'pointRadius': this.pointRadius,
            "strokeColor": strokeColor
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.TOO_SMALL] = {
            'fillColor': "#FF0000",
            'strokeWidth': 5,
            'pointRadius': this.pointRadius,
            "strokeColor": strokeColor
        };
        window.app.status.currentTermsCollection.each(function (term) {
            symbolizers_lookup[term.id] = {
                'fillColor': term.get('color'),
                'strokeWidth': 3,
                'pointRadius': self.pointRadius,
                "strokeColor": strokeColor
            }
        });
        return symbolizers_lookup
    },
    getSymbolizerReview: function (selected) {
        this.strokeColor = "#5BB75B";
        this.opacity = .8;
        this.strokeWidth = 5;
        this.strokeOpacity = 1;
        if (selected) {
            this.opacity = .5;
            this.strokeColor = "#006600";
            this.strokeWidth = 5;
        }

        var symbolizers_lookup = {};
        var self = this;
        //NO TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.NO_TERM] = {
            'fillColor': "#EEEEEE",
            "strokeColor": self.strokeColor,
            'fillOpacity': self.opacity,
            'strokeWidth': self.strokeWidth,
            'strokeOpacity': self.strokeOpacity,
            'pointRadius': this.pointRadius
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.MULTIPLE_TERM] = {
            'fillColor': "#CCCCCC",
            "strokeColor": self.strokeColor,
            'fillOpacity': self.opacity,
            'strokeWidth': self.strokeWidth,
            'strokeOpacity': self.strokeOpacity,
            'pointRadius': this.pointRadius
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.TOO_SMALL] = {
            'fillColor': "#FF0000",
            "strokeColor": self.strokeColor,
            'fillOpacity': self.opacity,
            'strokeWidth': self.strokeWidth,
            'strokeOpacity': self.strokeOpacity,
            'pointRadius': this.pointRadius
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.REVIEW] = {
            'fillColor': "#5BB75B",
            "strokeColor": self.strokeColor,
            'fillOpacity': self.opacity,
            'strokeWidth': self.strokeWidth,
            'strokeOpacity': self.strokeOpacity,
            'pointRadius': this.pointRadius
        };
        window.app.status.currentTermsCollection.each(function (term) {
            symbolizers_lookup[term.id] = {
                'fillColor': term.get('color'),
                "strokeColor": self.strokeColor,
                'fillOpacity': self.opacity,
                'strokeWidth': self.strokeWidth,
                'strokeOpacity': self.strokeOpacity,
                'pointRadius': this.pointRadius
            }
        });
        return symbolizers_lookup
    },
    getSymbolizerReviewNotReviewLayer: function (selected) {
        this.strokeColor = "#BD362F";
        this.opacity = .3;
        this.strokeWidth = 5;
        this.strokeOpacity = 1;
        if (selected) {
            this.opacity = .15;
            this.strokeColor = "#FF0000";
            this.strokeWidth = 5;
        }

        var symbolizers_lookup = {};
        var self = this;
        //NO TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.NO_TERM] = {
            'fillColor': "#EEEEEE",
            "strokeColor": self.strokeColor,
            'fillOpacity': self.opacity,
            'strokeWidth': self.strokeWidth,
            'strokeOpacity': self.strokeOpacity,
            'pointRadius': this.pointRadius

        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.MULTIPLE_TERM] = {
            'fillColor': "#CCCCCC",
            "strokeColor": self.strokeColor,
            'fillOpacity': self.opacity,
            'strokeWidth': self.strokeWidth,
            'strokeOpacity': self.strokeOpacity,
            'pointRadius': this.pointRadius
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.TOO_SMALL] = {
            'fillColor': "#FF0000",
            "strokeColor": self.strokeColor,
            'fillOpacity': self.opacity,
            'strokeWidth': self.strokeWidth,
            'strokeOpacity': self.strokeOpacity,
            'pointRadius': this.pointRadius
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.REVIEW] = {
            'fillColor': "#BD362F",
            "strokeColor": self.strokeColor,
            'fillOpacity': self.opacity,
            'strokeWidth': self.strokeWidth,
            'strokeOpacity': self.strokeOpacity,
            'pointRadius': this.pointRadius
        };
        window.app.status.currentTermsCollection.each(function (term) {
            symbolizers_lookup[term.id] = {
                'fillColor': term.get('color'),
                "strokeColor": self.strokeColor,
                'fillOpacity': self.opacity,
                'strokeWidth': self.strokeWidth,
                'strokeOpacity': self.strokeOpacity,
                'pointRadius': this.pointRadius
            }
        });
        return symbolizers_lookup
    },
    getSymbolizerRoi: function (selected) {

        var strokeColor = this.defaultStrokeColor;
        if (selected) {
            strokeColor = this.selectedStrokeColor;
        }
        var symbolizers_lookup = {};
        var self = this;
        //NO TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.NO_TERM] = {
            'fillColor': "#FCF8E3",
            'strokeWidth': 3,
            'pointRadius': this.pointRadius
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.MULTIPLE_TERM] = {
            'fillColor': "#FCF8E3",
            'strokeWidth': 3,
            'pointRadius': this.pointRadius
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.TOO_SMALL] = {
            'fillColor': "#FCF8E3",
            'strokeWidth': 5,
            'pointRadius': this.pointRadius
        };
        //MULTIPLE TERM ASSOCIATED
        symbolizers_lookup[AnnotationStatus.REVIEW] = {
            'fillColor': "#FCF8E3",
            'strokeWidth': 5,
            'pointRadius': this.pointRadius
        };


        return symbolizers_lookup
    },
    registerEvents: function (map) {

        var self = this;

        this.vectorsLayer.events.on({
            clickFeature: function (evt) {

            },
            onSelect: function (evt) {

            },
            featureselected: function (evt) {

                if (!self.measureOnSelect) {
                    self.ontologyTreeView.idAnnotation = evt.feature.attributes.idAnnotation;
                    self.ontologyTreeView.refresh(evt.feature.attributes.idAnnotation);

                    if (self.deleteOnSelect == true) {
                        self.removeSelection(false);
                    } else {
                        new AnnotationActionModel({
                            annotationIdent: evt.feature.attributes.idAnnotation,
                            action : "select"
                        }).save();
                        self.showPopup(map, evt);
                        self.browseImageView.jobTemplatePanel.changeAnnotation(evt.feature.attributes.idAnnotation);
                    }
                }
                else {
                    self.showPopupMeasure(map, evt);
                }

            },
            'featureunselected': function (evt) {
                console.log("featureunselected") ;
                if (self.measureOnSelect) {
                    self.vectorsLayer.removeFeatures(evt.feature);
                }

                if (self.dialog != null) {
                    self.dialog.destroy();
                }
                self.ontologyTreeView.clear();
                self.ontologyTreeView.clearAnnotation();
                self.browseImageView.showAnnotationInReviewPanel(null);
                self.clearPopup(map, evt);
                console.log("drawFeature:"+evt.feature) ;
                self.vectorsLayer.drawFeature(evt.feature);
            },
            'featureadded': function (evt) {
                /* Check if feature must throw a listener when it is added
                 * true: annotation already in database (no new insert!)
                 * false: new annotation that just have been draw (need insert)
                 * */
                if (!self.measureOnSelect) {
                    if (evt.feature.attributes.listener != 'NO') {

                        evt.feature.attributes.measure = 'YES';

                        if (self.browseImageView.freeHandUpdateAdd) {
                            self.correctAnnotation(evt.feature, false);
                        }
                        else if (self.browseImageView.freeHandUpdateRem) {
                            self.correctAnnotation(evt.feature, true);
                        }
                        else {
                            self.addAnnotation(evt.feature);
                        }
                    }
                }
                else {
                    self.controls.select.unselectAll();
                    self.controls.select.select(evt.feature);
                }

            },
            'sketchcomplete': function (evt) {
                if (self.triggerUpdateOnUnselect) {
                    self.updateAnnotation(evt,map);
                }
            },
            'featuremodified': function (evt) {
                //prevent to update an annotation when it is unnecessary
                if (self.triggerUpdateOnUnselect) {
                    self.updateAnnotation(evt,map);
                }
            },
            'onDelete': function (feature) {
            },
            "moveend": function () {
                self.clearPopup();
            }
        });
    },
    initControls: function (map, selectFeature) {

        this.controls = {
            'freehand': new OpenLayers.Control.DrawFeature(this.vectorsLayer, OpenLayers.Handler.Polygon, {
                handlerOptions: {
                    freehand: true,
                    holeModifier: "altKey"
                }
            }),
            'point': new OpenLayers.Control.DrawFeature(this.vectorsLayer, OpenLayers.Handler.Point, {
                handlerOptions: {
                    freehand: true,
                    style: {
                        fillColor: "#66cccc",
                        fillOpacity: 0.4,
                        strokeColor: "#66cccc",
                        strokeOpacity: 1,
                        strokeWidth: 2,
                        pointRadius: this.pointRadius
                    }
                }
            }),
            'line': new OpenLayers.Control.DrawFeature(this.vectorsLayer, OpenLayers.Handler.Path),
            'polygon': new OpenLayers.Control.DrawFeature(this.vectorsLayer, OpenLayers.Handler.Polygon, {
                handlerOptions: {
                    holeModifier: "altKey"
                }
            }),
            'regular': new OpenLayers.Control.DrawFeature(this.vectorsLayer, OpenLayers.Handler.RegularPolygon, {
                handlerOptions: {
                    sides: 5,
                    holeModifier: "altKey"
                }
            }),
            'modify': new OpenLayers.Control.ModifyFeature(this.vectorsLayer,{handlerOptions : {standalone:true}}),
            'select': selectFeature
        }
        this.controls.freehand.freehand = true;
        this.controls.freehand.freehandToggle = "altKey";

        map.initTools(this.controls);

    },
    loadAnnotations: function (browseImageView) {

        var self = this;
        console.log("AnnotationLayer.loadAnnotations");
        console.log("1");
        browseImageView.addVectorLayer(this, this.userID);
        console.log("2");
        browseImageView.layerLoadedCallback(self);
    },
    addFeature: function (feature) {
        this.vectorsLayer.addFeatures(feature);
    },
    selectFeature: function (feature) {
        this.controls.select.unselectAll();
        this.controls.select.select(feature);
    },
    removeFeature: function (idAnnotation) {
        var feature = this.getFeature(idAnnotation);
        this.vectorsLayer.removeFeatures(feature);
        this.ontologyTreeView.clearAnnotation();
        this.ontologyTreeView.clear();
    },
    getFeature: function (idAnnotation) {
        var features = this.vectorsLayer.getFeaturesByAttribute("idAnnotation", idAnnotation);
        if (_.isArray(features) && _.size(features) > 0) {
            return features[0];
        }
        return null;
    },
    removeSelection: function (reviewAction) {
        console.log("removeSelection");
        var self = this;
        for (var i in this.vectorsLayer.selectedFeatures) {
            var feature = this.vectorsLayer.selectedFeatures[i];
            if(reviewAction) {
                //if this method is call in review (accept/reject action), we simply delete it from the layer
                self.removeAnnotation(feature);
            } else {
                DialogModal.initDialogModal(null, feature.attributes.idAnnotation, 'Annotation', 'Do you want to delete this annotation ?', 'CONFIRMATIONWARNING', function(){
                    self.removeAnnotation(feature);
                });
            }

        }
    },
    clearPopup: function (map, evt) {
        var self = this;
        var elem = $("#" + self.browseImageView.divId).find("#annotationDetailPanel" + self.browseImageView.model.id);
        elem.empty();
        elem.hide();
    },
    hideFeature: function (feature) {
        var idAnnotation = feature.attributes.idAnnotation;
        if (_.indexOf(this.featuresHidden, idAnnotation) == -1) {
            this.featuresHidden.push(idAnnotation);
        }
        this.vectorsLayer.refresh();
    },
    showFeature: function (idAnnotation) {
        this.featuresHidden = _.without(this.featuresHidden, idAnnotation);
        this.vectorsLayer.refresh();
    },
    showPopup: function (map, evt) {
        var self = this;
        new AnnotationPopupPanel({
            browseImageView: self.browseImageView,
            idAnnotation :  evt.feature.attributes.idAnnotation,
            model: self.browseImageView.model,
            el: self.browseImageView.el
        }).render();
    },

    showPopupMeasure: function (map, evt) {
        var self = this;
        require([
            "text!application/templates/explorer/PopupMeasure.tpl.html"
        ], function (tpl) {
            if (evt.feature.popup != null) {
                return;
            }
            $("div#measure").remove();
            var resolution = self.browseImageView.model.get("resolution");
            var length = evt.feature.geometry.getLength();
            if (resolution != undefined && resolution != null) {
                length *= resolution;
                length = Math.round(length * 1000) / 1000;
                length += " µm";
            } else {
                length += " pixels";
            }
            var content = _.template(tpl, {length: length});


            self.popup = new OpenLayers.Popup("measure",
                new OpenLayers.LonLat(evt.feature.geometry.getBounds().right + 50, evt.feature.geometry.getBounds().bottom + 50),
                new OpenLayers.Size(200, 60),
                content,
                false);
            self.popup.setBackgroundColor("transparent");
            self.popup.setBorder(0);
            self.popup.padding = 0;

            evt.feature.popup = self.popup;
            self.popup.feature = evt.feature;
            map.addPopup(self.popup);
        });


    },
    enableHightlight: function () {
        //this.hoverControl.activate();
    },
    disableHightlight: function () {
        //this.hoverControl.deactivate();
    },
    correctAnnotation: function (feature, remove) {
        var self = this;

        var format = new OpenLayers.Format.WKT();
        var geomwkt = format.write(feature);

        if (geomwkt.indexOf("LINESTRING") != -1) {
            self.vectorsLayer.removeFeatures([feature]);
            return
        }

        var annotationCorrection = new AnnotationCorrectionModel({
            location: geomwkt,
            image: this.imageID,
            review: self.reviewMode,
            remove: remove,
            layers: self.browseImageView.getVisibleLayer()
        });

        annotationCorrection.save({}, {
            success: function (annotation, response) {
                window.app.view.message("Annotation updated", "Annotation updated with success", "success");
                _.each(self.browseImageView.getUserLayerCanEdit(),function(layer) {
                    layer.vectorsLayer.refresh();
                });
                if (self.reviewMode) {
                    self.browseImageView.refreshReviewLayer();
                }
                self.vectorsLayer.removeFeatures([feature]);
            },
            error: function (model, response) {
                var json = $.parseJSON(response.responseText);
                window.app.view.message("Cannot correct annotation", "error:" + json.errors, "error");
                self.vectorsLayer.removeFeatures([feature]);
            }
        });

    },


    /*Add annotation in database*/
    addAnnotation: function (feature) {

        var alias = this;
        var self = this;



        var format = new OpenLayers.Format.WKT();
        var geomwkt = format.write(feature);

        console.log(feature);
        if(self.browseImageView.arrow) {
            var point = feature.geometry
            console.log(point);
            var size = 300;
            var arrow = "POLYGON ((";
            arrow = arrow + point.x + " " + point.y + ", ";
            arrow = arrow + (point.x - size/2) + " " + (point.y- size/2) +",";
            arrow = arrow + (point.x - size/4) + " " + (point.y- size/2) +",";
            arrow = arrow + (point.x - size/4) + " " + (point.y- size*2) +",";
            arrow = arrow + (point.x + size/4) + " " + (point.y- size*2) +",";
            arrow = arrow + (point.x + size/4) + " " + (point.y- size/2) +",";
            arrow = arrow + (point.x + size/2) + " " + (point.y- size/2) +",";
            arrow = arrow + point.x + " " + point.y + "))";
            geomwkt = arrow;
        }



        var terms = alias.ontologyTreeView.getTermsChecked();
        var annotation = new AnnotationModel({
            name: "",
            location: geomwkt,
            image: this.imageID,
            term: terms,
            roi:self.browseImageView.roi
        });

        if (self.reviewMode && !self.browseImageView.reviewPanel.isLayerPrinted(window.app.status.user.id)) {
            window.app.view.message("Add annotation", "You must add your layer to add new annotation!", "error");
            self.vectorsLayer.removeFeatures([feature]);
            return;
        }

        if(!self.drawable) return;
        annotation.set({user: self.userID});
        annotation.save({user: self.userID}, {
            success: function (annotation, response) {
                new AnnotationModel({id: response.annotation.id}).fetch({
                    success: function (annotation, response) {
                        var message = response.message;
                        self.vectorsLayer.removeFeatures([feature]);
                        var newFeature = AnnotationLayerUtils.createFeatureFromAnnotation(annotation);
                        self.addFeature(newFeature);
                        self.controls.select.unselectAll();
                        self.controls.select.select(newFeature);
                        var alertMessage = _.template("<p></p><div></div>", { message: message});
                        window.app.view.message("Annotation added", alertMessage, "success");
                    }
                });

            },
            error: function (model, response) {
                var json = $.parseJSON(response.responseText);
                window.app.view.message("Add annotation", "error:" + json.errors, "error");
            }
        });


    },
    removeAnnotation: function (feature) {
        var self = this;
        feature.destroyPopup();
        this.removeFeature(feature);
        this.controls.select.unselectAll();
        this.vectorsLayer.removeFeatures([feature]);
        new AnnotationModel({id: feature.attributes.idAnnotation}).destroy({
            success: function (model, response) {
                window.app.view.message("Annotation", response.message, "success");
                //TODO find a way to just hide the feature when asking for delete and truly delete it if success. Else, re-show the feature
                //END todo
                self.browseImageView.refreshAnnotationTabs(undefined);

            },
            error: function (model, response) {
                var json = $.parseJSON(response.responseText);
                window.app.view.message("Annotation", json.errors, "error",5000);
            }
        });
    },

    /*Modifiy annotation on database*/
    updateAnnotation: function (evt,map) {
        if (evt.feature.attributes.idAnnotation == undefined) {
            return;
        }
        var self = this;
        var format = new OpenLayers.Format.WKT();
        var geomwkt = format.write(evt.feature);
        new AnnotationModel({id: evt.feature.attributes.idAnnotation}).fetch({
            success: function (model, response) {

                model.save({location: geomwkt}, {
                    success: function (annotation, response) {
                        var message = response.message;
                        var alertMessage = _.template("<p><%=   message %></p>", { message: message});
                        window.app.view.message("Annotation edited", alertMessage, "success");
                        self.showPopup(map, evt);
                    },
                    error: function (model, response) {
                        var json = $.parseJSON(response.responseText);
                        window.app.view.message("Annotation", json.errors, "");
                    }
                });
            }
        });
    },
    toggleRotate: function () {
        this.resize = false;
        this.drag = false;
        this.rotate = true;
        this.fill = false;
        this.updateControls();
        this.toggleControl("modify");
    },
    toggleFill: function () {
        this.resize = false;
        this.drag = false;
        this.rotate = false;
        this.fill = true;
        this.updateControls();
        this.toggleControl("modify");
    },
    toggleResize: function () {
        this.resize = true;
        this.drag = false;
        this.rotate = false;
        this.fill = false;
        this.updateControls();
        this.toggleControl("modify");
    },
    toggleDrag: function () {
        this.resize = false;
        this.drag = true;
        this.rotate = false;
        this.fill = false;
        this.updateControls();
        this.toggleControl("modify");

    },
    toggleEdit: function () {
        this.resize = false;
        this.drag = false;
        this.rotate = false;
        this.fill = false;
        this.updateControls();
        this.toggleControl("modify");

    },
    toggleIrregular: function () {

        this.irregular = !this.irregular;
        this.updateControls();
    },
    toggleAspectRatio: function () {
        this.aspectRatio = !this.aspectRatio;
        this.updateControls();
    },
    setSides: function (sides) {
        this.sides = sides;
        this.updateControls();
    },
    updateControls: function () {

        this.controls.modify.mode = OpenLayers.Control.ModifyFeature.RESHAPE;
        if (this.rotate) {
            this.controls.modify.mode |= OpenLayers.Control.ModifyFeature.ROTATE;
        }

        if (this.resize) {
            this.controls.modify.mode |= OpenLayers.Control.ModifyFeature.RESIZE;
            if (this.aspectRatio) {
                this.controls.modify.mode &= ~OpenLayers.Control.ModifyFeature.RESHAPE;
            }
        }
        if (this.drag) {
            this.controls.modify.mode |= OpenLayers.Control.ModifyFeature.DRAG;
        }
        if (this.rotate || this.drag) {
            this.controls.modify.mode &= ~OpenLayers.Control.ModifyFeature.RESHAPE;
        }0
        this.controls.regular.handler.sides = this.sides;
        this.controls.regular.handler.irregular = this.irregular;
    },
    disableMeasureOnSelect: function () {
        var self = this;
        this.measureOnSelect = false;
        //browse measure on select
        for (var i in this.vectorsLayer.features) {
            var feature = this.vectorsLayer.features[i];

            if (feature.attributes == undefined || feature.attributes.measure == undefined || feature.attributes.measure == 'YES') {
                self.vectorsLayer.removeFeatures(feature);
                if (feature.popup) {
                    self.popup.feature = null;
                    self.map.removePopup(feature.popup);
                    feature.popup.destroy();
                    feature.popup = null;
                    self.popup = null;
                }

            }
        }
    },
    toggleControl: function (name) {
        //Simulate an OpenLayers.Control.EraseFeature tool by using SelectFeature with the flag 'deleteOnSelect'
        this.deleteOnSelect = false;
        this.disableMeasureOnSelect();
        this.magicOnClick = false;
        for (key in this.controls) {
            var control = this.controls[key];
            if (name == key || key == "select") {
                if(!control.active) {control.activate();}

                if (control == this.controls.modify) {
                    for (var i in this.vectorsLayer.selectedFeatures) {
                        var feature = this.vectorsLayer.selectedFeatures[i];
                        control.selectFeature(feature);
                    }
                }
            } else {
                control.deactivate();
                if (control === this.controls.modify) {
                    for (var i in this.vectorsLayer.selectedFeatures) {
                        var feature = this.vectorsLayer.selectedFeatures[i];
                        try{
                              control.unselectFeature(feature);
                        }
                        catch(err) {
                          //Handle errors here
                            console.log(err);
                          }
                    }

                }
            }
        }

    },
    /* Callbacks undo/redo */
    annotationAdded: function (idAnnotation) {
        var self = this;
        var deleteOnSelectBackup = self.deleteOnSelect;
        self.deleteOnSelect = false;
        new AnnotationModel({
            id: idAnnotation
        }).fetch({
                success: function (model) {
                    var feature = AnnotationLayerUtils.createFeatureFromAnnotation(model);
                    self.addFeature(feature);
                    self.selectFeature(feature);
                    self.controls.select.activate();
                    self.deleteOnSelect = deleteOnSelectBackup;
                }
            });

    },
    annotationRemoved: function (idAnnotation) {
        this.removeFeature(idAnnotation);
    },
    annotationUpdated: function (idAnnotation, idImage) {
        this.annotationRemoved(idAnnotation);
        this.annotationAdded(idAnnotation);

    },
    termAdded: function (idAnnotation, idTerm) {
        this.annotationRemoved(idAnnotation);
        this.annotationAdded(idAnnotation);
    },
    termRemoved: function (idAnnotation, idTerm) {
        this.annotationRemoved(idAnnotation);
        this.annotationAdded(idAnnotation);
    },
    isVisible: function () {
        return this.vectorsLayer.visibility
    }
};
