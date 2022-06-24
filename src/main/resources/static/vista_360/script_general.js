(function(){
var translateObjs = {};
function trans(c, d) {
    var e = arguments['length'] === 0x1 ? [arguments[0x0]] : Array['apply'](null, arguments);
    translateObjs[e[0x0]] = e;
    return '';
}
function regTextVar(f, g) {
    var h = ![];
    g = g['toLowerCase']();
    var i = function () {
        var r = this['get']('data');
        r['updateText'](r['translateObjs'][f]);
    };
    var j = function (s) {
        var t = s['data']['nextSelectedIndex'];
        if (t >= 0x0) {
            var u = s['source']['get']('items')[t];
            var v = function () {
                u['unbind']('start', v, this);
                i['call'](this);
            };
            u['bind']('start', v, this);
        } else
            i['call'](this);
    };
    var k = function (w) {
        return function (x) {
            if (w in x) {
                i['call'](this);
            }
        }['bind'](this);
    };
    var l = function (y, z) {
        return function (A, B) {
            if (y == A && z in B) {
                i['call'](this);
            }
        }['bind'](this);
    };
    var m = function (C, D, E) {
        for (var F = 0x0; F < C['length']; ++F) {
            var G = C[F];
            var H = G['get']('selectedIndex');
            if (H >= 0x0) {
                var I = D['split']('.');
                var J = G['get']('items')[H];
                if (E !== undefined && !E['call'](this, J))
                    continue;
                for (var K = 0x0; K < I['length']; ++K) {
                    if (J == undefined)
                        return '';
                    J = 'get' in J ? J['get'](I[K]) : J[I[K]];
                }
                return J;
            }
        }
        return '';
    };
    var n = function (L) {
        var M = L['get']('player');
        return M !== undefined && M['get']('viewerArea') == this['getMainViewer']();
    };
    switch (g) {
    case 'title':
    case 'subtitle':
        var p = function () {
            switch (g) {
            case 'title':
                return 'media.label';
            case 'subtitle':
                return 'media.data.subtitle';
            }
        }();
        if (p) {
            return function () {
                var N = this['_getPlayListsWithViewer'](this['getMainViewer']());
                if (!h) {
                    for (var O = 0x0; O < N['length']; ++O) {
                        N[O]['bind']('changing', j, this);
                    }
                    h = !![];
                }
                return m['call'](this, N, p, n);
            };
        }
        break;
    default:
        if (g['startsWith']('quiz.') && 'Quiz' in TDV) {
            var q = undefined;
            var p = function () {
                switch (g) {
                case 'quiz.questions.answered':
                    return TDV['Quiz']['PROPERTY']['QUESTIONS_ANSWERED'];
                case 'quiz.question.count':
                    return TDV['Quiz']['PROPERTY']['QUESTION_COUNT'];
                case 'quiz.items.found':
                    return TDV['Quiz']['PROPERTY']['ITEMS_FOUND'];
                case 'quiz.item.count':
                    return TDV['Quiz']['PROPERTY']['ITEM_COUNT'];
                case 'quiz.score':
                    return TDV['Quiz']['PROPERTY']['SCORE'];
                case 'quiz.score.total':
                    return TDV['Quiz']['PROPERTY']['TOTAL_SCORE'];
                case 'quiz.time.remaining':
                    return TDV['Quiz']['PROPERTY']['REMAINING_TIME'];
                case 'quiz.time.elapsed':
                    return TDV['Quiz']['PROPERTY']['ELAPSED_TIME'];
                case 'quiz.time.limit':
                    return TDV['Quiz']['PROPERTY']['TIME_LIMIT'];
                case 'quiz.media.items.found':
                    return TDV['Quiz']['PROPERTY']['PANORAMA_ITEMS_FOUND'];
                case 'quiz.media.item.count':
                    return TDV['Quiz']['PROPERTY']['PANORAMA_ITEM_COUNT'];
                case 'quiz.media.questions.answered':
                    return TDV['Quiz']['PROPERTY']['PANORAMA_QUESTIONS_ANSWERED'];
                case 'quiz.media.question.count':
                    return TDV['Quiz']['PROPERTY']['PANORAMA_QUESTION_COUNT'];
                case 'quiz.media.score':
                    return TDV['Quiz']['PROPERTY']['PANORAMA_SCORE'];
                case 'quiz.media.score.total':
                    return TDV['Quiz']['PROPERTY']['PANORAMA_TOTAL_SCORE'];
                case 'quiz.media.index':
                    return TDV['Quiz']['PROPERTY']['PANORAMA_INDEX'];
                case 'quiz.media.count':
                    return TDV['Quiz']['PROPERTY']['PANORAMA_COUNT'];
                case 'quiz.media.visited':
                    return TDV['Quiz']['PROPERTY']['PANORAMA_VISITED_COUNT'];
                default:
                    var P = /quiz\.([\w_]+)\.(.+)/['exec'](g);
                    if (P) {
                        q = P[0x1];
                        switch ('quiz.' + P[0x2]) {
                        case 'quiz.score':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['SCORE'];
                        case 'quiz.score.total':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['TOTAL_SCORE'];
                        case 'quiz.media.items.found':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['PANORAMA_ITEMS_FOUND'];
                        case 'quiz.media.item.count':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['PANORAMA_ITEM_COUNT'];
                        case 'quiz.media.questions.answered':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['PANORAMA_QUESTIONS_ANSWERED'];
                        case 'quiz.media.question.count':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['PANORAMA_QUESTION_COUNT'];
                        case 'quiz.questions.answered':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['QUESTIONS_ANSWERED'];
                        case 'quiz.question.count':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['QUESTION_COUNT'];
                        case 'quiz.items.found':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['ITEMS_FOUND'];
                        case 'quiz.item.count':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['ITEM_COUNT'];
                        case 'quiz.media.score':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['PANORAMA_SCORE'];
                        case 'quiz.media.score.total':
                            return TDV['Quiz']['OBJECTIVE_PROPERTY']['PANORAMA_TOTAL_SCORE'];
                        }
                    }
                }
            }();
            if (p) {
                return function () {
                    var Q = this['get']('data')['quiz'];
                    if (Q) {
                        if (!h) {
                            if (q != undefined)
                                if (q == 'global') {
                                    var S = this['get']('data')['quizConfig'];
                                    var U = S['objectives'];
                                    for (var W = 0x0, Y = U['length']; W < Y; ++W) {
                                        Q['bind'](TDV['Quiz']['EVENT_OBJECTIVE_PROPERTIES_CHANGE'], l['call'](this, U[W]['id'], p), this);
                                    }
                                } else {
                                    Q['bind'](TDV['Quiz']['EVENT_OBJECTIVE_PROPERTIES_CHANGE'], l['call'](this, q, p), this);
                                }
                            else
                                Q['bind'](TDV['Quiz']['EVENT_PROPERTIES_CHANGE'], k['call'](this, p), this);
                            h = !![];
                        }
                        try {
                            var Z = 0x0;
                            if (q != undefined) {
                                if (q == 'global') {
                                    var S = this['get']('data')['quizConfig'];
                                    var U = S['objectives'];
                                    for (var W = 0x0, Y = U['length']; W < Y; ++W) {
                                        Z += Q['getObjective'](U[W]['id'], p);
                                    }
                                } else {
                                    Z = Q['getObjective'](q, p);
                                }
                            } else {
                                Z = Q['get'](p);
                                if (p == TDV['Quiz']['PROPERTY']['PANORAMA_INDEX'])
                                    Z += 0x1;
                            }
                            return Z;
                        } catch (a0) {
                            return undefined;
                        }
                    }
                };
            }
        }
        break;
    }
    return '';
}
function createQuizConfig(player, a1) {
    var a2 = {};
    a2['player'] = player;
    a2['playList'] = a1;
    function a3(a6) {
        for (var a7 = 0x0; a7 < a6['length']; ++a7) {
            var a8 = a6[a7];
            if ('id' in a8)
                player[a8['id']] = a8;
        }
    }
    if (a2['questions']) {
        a3(a2['questions']);
        for (var a4 = 0x0; a4 < a2['questions']['length']; ++a4) {
            var a5 = a2['questions'][a4];
            a3(a5['options']);
        }
    }
    if (a2['objectives']) {
        a3(a2['objectives']);
    }
    if (a2['califications']) {
        a3(a2['califications']);
    }
    if (a2['score']) {
        player[a2['score']['id']] = a2['score'];
    }
    if (a2['question']) {
        player[a2['question']['id']] = a2['question'];
    }
    if (a2['timeout']) {
        player[a2['timeout']['id']] = a2['timeout'];
    }
    player['get']('data')['translateObjs'] = translateObjs;
    return a2;
}
var script = {"start":"this.get('data').surfaceSelectionHotspotMode = 'circleEnabled'; this.init()","borderSize":0,"backgroundOpacity":1,"paddingLeft":0,"mobileMipmappingEnabled":false,"width":"100%","class":"Player","paddingRight":0,"id":"rootPlayer","downloadEnabled":true,"paddingTop":0,"defaultMenu":["fullscreen","mute","rotation"],"paddingBottom":0,"mouseWheelEnabled":true,"horizontalAlign":"left","children":["this.MainViewer"],"backgroundColorDirection":"vertical","borderRadius":0,"scrollBarColor":"#000000","overflow":"hidden","desktopMipmappingEnabled":false,"scrollBarWidth":10,"layout":"absolute","verticalAlign":"top","backgroundColor":["#FFFFFF"],"height":"100%","scrollBarOpacity":0.5,"scripts":{"setMediaBehaviour":TDV.Tour.Script.setMediaBehaviour,"translate":TDV.Tour.Script.translate,"setMainMediaByIndex":TDV.Tour.Script.setMainMediaByIndex,"playGlobalAudioWhilePlayActiveMedia":TDV.Tour.Script.playGlobalAudioWhilePlayActiveMedia,"showWindow":TDV.Tour.Script.showWindow,"updateMediaLabelFromPlayList":TDV.Tour.Script.updateMediaLabelFromPlayList,"showPopupPanoramaOverlay":TDV.Tour.Script.showPopupPanoramaOverlay,"triggerOverlay":TDV.Tour.Script.triggerOverlay,"getComponentByName":TDV.Tour.Script.getComponentByName,"stopAndGoCamera":TDV.Tour.Script.stopAndGoCamera,"shareSocial":TDV.Tour.Script.shareSocial,"visibleComponentsIfPlayerFlagEnabled":TDV.Tour.Script.visibleComponentsIfPlayerFlagEnabled,"_getObjectsByTags":TDV.Tour.Script._getObjectsByTags,"getPanoramaOverlaysByTags":TDV.Tour.Script.getPanoramaOverlaysByTags,"setComponentsVisibilityByTags":TDV.Tour.Script.setComponentsVisibilityByTags,"getActiveMediaWithViewer":TDV.Tour.Script.getActiveMediaWithViewer,"getMediaByName":TDV.Tour.Script.getMediaByName,"setEndToItemIndex":TDV.Tour.Script.setEndToItemIndex,"getMediaHeight":TDV.Tour.Script.getMediaHeight,"quizSetItemFound":TDV.Tour.Script.quizSetItemFound,"getKey":TDV.Tour.Script.getKey,"setMapLocation":TDV.Tour.Script.setMapLocation,"executeFunctionWhenChange":TDV.Tour.Script.executeFunctionWhenChange,"pauseGlobalAudio":TDV.Tour.Script.pauseGlobalAudio,"setCameraSameSpotAsMedia":TDV.Tour.Script.setCameraSameSpotAsMedia,"openLink":TDV.Tour.Script.openLink,"keepCompVisible":TDV.Tour.Script.keepCompVisible,"startPanoramaWithCamera":TDV.Tour.Script.startPanoramaWithCamera,"unregisterKey":TDV.Tour.Script.unregisterKey,"textToSpeechComponent":TDV.Tour.Script.textToSpeechComponent,"pauseGlobalAudios":TDV.Tour.Script.pauseGlobalAudios,"init":TDV.Tour.Script.init,"getFirstPlayListWithMedia":TDV.Tour.Script.getFirstPlayListWithMedia,"stopGlobalAudios":TDV.Tour.Script.stopGlobalAudios,"showComponentsWhileMouseOver":TDV.Tour.Script.showComponentsWhileMouseOver,"showPopupPanoramaVideoOverlay":TDV.Tour.Script.showPopupPanoramaVideoOverlay,"isPanorama":TDV.Tour.Script.isPanorama,"getOverlays":TDV.Tour.Script.getOverlays,"getPlayListItems":TDV.Tour.Script.getPlayListItems,"clone":TDV.Tour.Script.clone,"getMediaByTags":TDV.Tour.Script.getMediaByTags,"openEmbeddedPDF":TDV.Tour.Script.openEmbeddedPDF,"getMainViewer":TDV.Tour.Script.getMainViewer,"getPlayListsWithMedia":TDV.Tour.Script.getPlayListsWithMedia,"syncPlaylists":TDV.Tour.Script.syncPlaylists,"copyObjRecursively":TDV.Tour.Script.copyObjRecursively,"getOverlaysByGroupname":TDV.Tour.Script.getOverlaysByGroupname,"getComponentsByTags":TDV.Tour.Script.getComponentsByTags,"executeAudioAction":TDV.Tour.Script.executeAudioAction,"getActivePlayerWithViewer":TDV.Tour.Script.getActivePlayerWithViewer,"_initSplitViewer":TDV.Tour.Script._initSplitViewer,"fixTogglePlayPauseButton":TDV.Tour.Script.fixTogglePlayPauseButton,"setSurfaceSelectionHotspotMode":TDV.Tour.Script.setSurfaceSelectionHotspotMode,"takeScreenshot":TDV.Tour.Script.takeScreenshot,"downloadFile":TDV.Tour.Script.downloadFile,"showPopupMedia":TDV.Tour.Script.showPopupMedia,"registerKey":TDV.Tour.Script.registerKey,"setComponentVisibility":TDV.Tour.Script.setComponentVisibility,"pauseGlobalAudiosWhilePlayItem":TDV.Tour.Script.pauseGlobalAudiosWhilePlayItem,"assignObjRecursively":TDV.Tour.Script.assignObjRecursively,"_initItemWithComps":TDV.Tour.Script._initItemWithComps,"setStartTimeVideo":TDV.Tour.Script.setStartTimeVideo,"sendAnalyticsData":TDV.Tour.Script.sendAnalyticsData,"getAudioByTags":TDV.Tour.Script.getAudioByTags,"resumeGlobalAudios":TDV.Tour.Script.resumeGlobalAudios,"resumePlayers":TDV.Tour.Script.resumePlayers,"getRootOverlay":TDV.Tour.Script.getRootOverlay,"loadFromCurrentMediaPlayList":TDV.Tour.Script.loadFromCurrentMediaPlayList,"updateVideoCues":TDV.Tour.Script.updateVideoCues,"getPlayListItemIndexByMedia":TDV.Tour.Script.getPlayListItemIndexByMedia,"cloneBindings":TDV.Tour.Script.cloneBindings,"pauseCurrentPlayers":TDV.Tour.Script.pauseCurrentPlayers,"executeAudioActionByTags":TDV.Tour.Script.executeAudioActionByTags,"setPanoramaCameraWithCurrentSpot":TDV.Tour.Script.setPanoramaCameraWithCurrentSpot,"setStartTimeVideoSync":TDV.Tour.Script.setStartTimeVideoSync,"getPanoramaOverlayByName":TDV.Tour.Script.getPanoramaOverlayByName,"initAnalytics":TDV.Tour.Script.initAnalytics,"quizShowScore":TDV.Tour.Script.quizShowScore,"quizShowTimeout":TDV.Tour.Script.quizShowTimeout,"copyToClipboard":TDV.Tour.Script.copyToClipboard,"quizPauseTimer":TDV.Tour.Script.quizPauseTimer,"changeBackgroundWhilePlay":TDV.Tour.Script.changeBackgroundWhilePlay,"getCurrentPlayerWithMedia":TDV.Tour.Script.getCurrentPlayerWithMedia,"changeOpacityWhilePlay":TDV.Tour.Script.changeOpacityWhilePlay,"stopTextToSpeech":TDV.Tour.Script.stopTextToSpeech,"stopGlobalAudio":TDV.Tour.Script.stopGlobalAudio,"setDirectionalPanoramaAudio":TDV.Tour.Script.setDirectionalPanoramaAudio,"playAudioList":TDV.Tour.Script.playAudioList,"quizStart":TDV.Tour.Script.quizStart,"initQuiz":TDV.Tour.Script.initQuiz,"historyGoForward":TDV.Tour.Script.historyGoForward,"setPanoramaCameraWithSpot":TDV.Tour.Script.setPanoramaCameraWithSpot,"mixObject":TDV.Tour.Script.mixObject,"getOverlaysByTags":TDV.Tour.Script.getOverlaysByTags,"getMediaFromPlayer":TDV.Tour.Script.getMediaFromPlayer,"autotriggerAtStart":TDV.Tour.Script.autotriggerAtStart,"setValue":TDV.Tour.Script.setValue,"getPixels":TDV.Tour.Script.getPixels,"_initTwinsViewer":TDV.Tour.Script._initTwinsViewer,"isCardboardViewMode":TDV.Tour.Script.isCardboardViewMode,"setLocale":TDV.Tour.Script.setLocale,"quizResumeTimer":TDV.Tour.Script.quizResumeTimer,"historyGoBack":TDV.Tour.Script.historyGoBack,"executeJS":TDV.Tour.Script.executeJS,"setMainMediaByName":TDV.Tour.Script.setMainMediaByName,"existsKey":TDV.Tour.Script.existsKey,"skip3DTransitionOnce":TDV.Tour.Script.skip3DTransitionOnce,"cloneCamera":TDV.Tour.Script.cloneCamera,"getGlobalAudio":TDV.Tour.Script.getGlobalAudio,"quizFinish":TDV.Tour.Script.quizFinish,"showPopupImage":TDV.Tour.Script.showPopupImage,"setOverlaysVisibility":TDV.Tour.Script.setOverlaysVisibility,"getPlayListWithItem":TDV.Tour.Script.getPlayListWithItem,"getPlayListItemByMedia":TDV.Tour.Script.getPlayListItemByMedia,"setOverlaysVisibilityByTags":TDV.Tour.Script.setOverlaysVisibilityByTags,"textToSpeech":TDV.Tour.Script.textToSpeech,"playGlobalAudio":TDV.Tour.Script.playGlobalAudio,"initOverlayGroupRotationOnClick":TDV.Tour.Script.initOverlayGroupRotationOnClick,"playGlobalAudioWhilePlay":TDV.Tour.Script.playGlobalAudioWhilePlay,"updateDeepLink":TDV.Tour.Script.updateDeepLink,"quizShowQuestion":TDV.Tour.Script.quizShowQuestion,"setOverlayBehaviour":TDV.Tour.Script.setOverlayBehaviour,"_getPlayListsWithViewer":TDV.Tour.Script._getPlayListsWithViewer,"_initTTSTooltips":TDV.Tour.Script._initTTSTooltips,"changePlayListWithSameSpot":TDV.Tour.Script.changePlayListWithSameSpot,"getMediaWidth":TDV.Tour.Script.getMediaWidth,"htmlToPlainText":TDV.Tour.Script.htmlToPlainText,"getCurrentPlayers":TDV.Tour.Script.getCurrentPlayers},"vrPolyfillScale":0.75,"definitions": [{"class":"PlayList","items":[{"camera":"this.panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7_camera","media":"this.panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7","class":"PanoramaPlayListItem","begin":"this.setEndToItemIndex(this.mainPlayList, 0, 1)","player":"this.MainViewerPanoramaPlayer"},{"camera":"this.panorama_53A59D81_588D_9F1A_41C3_F46603C7778F_camera","media":"this.panorama_53A59D81_588D_9F1A_41C3_F46603C7778F","class":"PanoramaPlayListItem","begin":"this.setEndToItemIndex(this.mainPlayList, 1, 2)","player":"this.MainViewerPanoramaPlayer"},{"camera":"this.panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32_camera","media":"this.panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32","class":"PanoramaPlayListItem","begin":"this.setEndToItemIndex(this.mainPlayList, 2, 3)","player":"this.MainViewerPanoramaPlayer"},{"class":"PanoramaPlayListItem","camera":"this.panorama_511E66F1_5895_EAFA_41B0_3C3E97613546_camera","player":"this.MainViewerPanoramaPlayer","media":"this.panorama_511E66F1_5895_EAFA_41B0_3C3E97613546"},{"camera":"this.panorama_511EB481_5895_ED1B_41C3_BB36B99D7268_camera","media":"this.panorama_511EB481_5895_ED1B_41C3_BB36B99D7268","class":"PanoramaPlayListItem","player":"this.MainViewerPanoramaPlayer","end":"this.trigger('tourEnded')"}],"id":"mainPlayList"},{"automaticZoomSpeed":10,"hoverFactor":0,"initialSequence":"this.sequence_62E611D3_6F0F_61F3_41AC_587B3AA2BA94","class":"PanoramaCamera","initialPosition":{"class":"PanoramaCameraPosition","yaw":29.1,"pitch":0.6},"id":"panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7_camera"},{"hfov":65,"label":trans('panorama_511E66F1_5895_EAFA_41B0_3C3E97613546.label'),"thumbnailUrl":"media/panorama_511E66F1_5895_EAFA_41B0_3C3E97613546_t.jpg","frames":[{"class":"CubicPanoramaFrame","front":{"class":"ImageResource","levels":[{"height":8192,"width":8192,"url":"media/panorama_511E66F1_5895_EAFA_41B0_3C3E97613546_0/f/0/{row}_{column}.jpg","rowCount":16,"class":"TiledImageResourceLevel","colCount":16,"tags":"ondemand"},{"height":4096,"width":4096,"url":"media/panorama_511E66F1_5895_EAFA_41B0_3C3E97613546_0/f/1/{row}_{column}.jpg","rowCount":8,"class":"TiledImageResourceLevel","colCount":8,"tags":"ondemand"},{"height":2048,"width":2048,"url":"media/panorama_511E66F1_5895_EAFA_41B0_3C3E97613546_0/f/2/{row}_{column}.jpg","rowCount":4,"class":"TiledImageResourceLevel","colCount":4,"tags":"ondemand"},{"height":1024,"width":1024,"url":"media/panorama_511E66F1_5895_EAFA_41B0_3C3E97613546_0/f/3/{row}_{column}.jpg","rowCount":2,"class":"TiledImageResourceLevel","colCount":2,"tags":"ondemand"},{"height":512,"width":512,"url":"media/panorama_511E66F1_5895_EAFA_41B0_3C3E97613546_0/f/4/{row}_{column}.jpg","rowCount":1,"class":"TiledImageResourceLevel","colCount":1,"tags":["ondemand","preload"]}]},"thumbnailUrl":"media/panorama_511E66F1_5895_EAFA_41B0_3C3E97613546_t.jpg"}],"partial":true,"hfovMin":"150%","vfov":48.75,"class":"Panorama","hfovMax":65,"data":{"label":"4"},"pitch":7.15,"id":"panorama_511E66F1_5895_EAFA_41B0_3C3E97613546"},{"hfov":65,"label":trans('panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32.label'),"thumbnailUrl":"media/panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32_t.jpg","frames":[{"class":"CubicPanoramaFrame","front":{"class":"ImageResource","levels":[{"height":8192,"width":8192,"url":"media/panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32_0/f/0/{row}_{column}.jpg","rowCount":16,"class":"TiledImageResourceLevel","colCount":16,"tags":"ondemand"},{"height":4096,"width":4096,"url":"media/panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32_0/f/1/{row}_{column}.jpg","rowCount":8,"class":"TiledImageResourceLevel","colCount":8,"tags":"ondemand"},{"height":2048,"width":2048,"url":"media/panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32_0/f/2/{row}_{column}.jpg","rowCount":4,"class":"TiledImageResourceLevel","colCount":4,"tags":"ondemand"},{"height":1024,"width":1024,"url":"media/panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32_0/f/3/{row}_{column}.jpg","rowCount":2,"class":"TiledImageResourceLevel","colCount":2,"tags":"ondemand"},{"height":512,"width":512,"url":"media/panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32_0/f/4/{row}_{column}.jpg","rowCount":1,"class":"TiledImageResourceLevel","colCount":1,"tags":["ondemand","preload"]}]},"thumbnailUrl":"media/panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32_t.jpg"}],"partial":true,"hfovMin":"150%","vfov":48.75,"class":"Panorama","hfovMax":65,"data":{"label":"3"},"pitch":7.15,"id":"panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32"},{"automaticZoomSpeed":10,"hoverFactor":0,"initialSequence":{"class":"PanoramaCameraSequence","movements":[{"yawSpeed":1.38,"easing":"quad_in_out","targetYaw":27.27,"targetPitch":6.74,"class":"TargetPanoramaCameraMovement","pitchSpeed":1.28,"path":"shortest"},{"yawSpeed":1.38,"easing":"quad_in_out","targetYaw":-30.21,"targetPitch":6.66,"class":"TargetPanoramaCameraMovement","pitchSpeed":1.28,"path":"shortest","end":"this.mainPlayList.set('selectedIndex', 4)"}],"restartMovementOnUserInteraction":false},"class":"PanoramaCamera","initialPosition":{"class":"PanoramaCameraPosition","yaw":0,"pitch":7.15},"id":"panorama_511E66F1_5895_EAFA_41B0_3C3E97613546_camera"},{"hfov":65,"label":trans('panorama_511EB481_5895_ED1B_41C3_BB36B99D7268.label'),"thumbnailUrl":"media/panorama_511EB481_5895_ED1B_41C3_BB36B99D7268_t.jpg","frames":[{"class":"CubicPanoramaFrame","front":{"class":"ImageResource","levels":[{"height":8192,"width":8192,"url":"media/panorama_511EB481_5895_ED1B_41C3_BB36B99D7268_0/f/0/{row}_{column}.jpg","rowCount":16,"class":"TiledImageResourceLevel","colCount":16,"tags":"ondemand"},{"height":4096,"width":4096,"url":"media/panorama_511EB481_5895_ED1B_41C3_BB36B99D7268_0/f/1/{row}_{column}.jpg","rowCount":8,"class":"TiledImageResourceLevel","colCount":8,"tags":"ondemand"},{"height":2048,"width":2048,"url":"media/panorama_511EB481_5895_ED1B_41C3_BB36B99D7268_0/f/2/{row}_{column}.jpg","rowCount":4,"class":"TiledImageResourceLevel","colCount":4,"tags":"ondemand"},{"height":1024,"width":1024,"url":"media/panorama_511EB481_5895_ED1B_41C3_BB36B99D7268_0/f/3/{row}_{column}.jpg","rowCount":2,"class":"TiledImageResourceLevel","colCount":2,"tags":"ondemand"},{"height":512,"width":512,"url":"media/panorama_511EB481_5895_ED1B_41C3_BB36B99D7268_0/f/4/{row}_{column}.jpg","rowCount":1,"class":"TiledImageResourceLevel","colCount":1,"tags":["ondemand","preload"]}]},"thumbnailUrl":"media/panorama_511EB481_5895_ED1B_41C3_BB36B99D7268_t.jpg"}],"partial":true,"hfovMin":"150%","vfov":48.75,"class":"Panorama","hfovMax":65,"data":{"label":"5"},"pitch":5.85,"id":"panorama_511EB481_5895_ED1B_41C3_BB36B99D7268"},{"automaticZoomSpeed":10,"hoverFactor":0,"initialSequence":"this.sequence_63C5760B_6F0D_6252_41D8_DCFBE890066A","class":"PanoramaCamera","initialPosition":{"class":"PanoramaCameraPosition","yaw":0,"pitch":-0.64},"id":"panorama_53A59D81_588D_9F1A_41C3_F46603C7778F_camera"},{"aaEnabled":true,"displayPlaybackBar":true,"gyroscopeEnabled":true,"gyroscopeVerticalDraggingEnabled":true,"id":"MainViewerPanoramaPlayer","surfaceSelectionEnabled":true,"touchControlMode":"drag_rotation","mouseControlMode":"drag_rotation","viewerArea":"this.MainViewer","adjacentPanoramaPositionsEnabled":true,"class":"PanoramaPlayer","zoomEnabled":true,"arrowKeysAction":"translate"},{"playbackBarOpacity":1,"subtitlesBorderSize":0,"playbackBarHeadShadowColor":"#000000","borderSize":0,"paddingLeft":0,"progressBackgroundOpacity":1,"vrPointerColor":"#FFFFFF","playbackBarHeadBackgroundColor":["#111111","#666666"],"progressBorderRadius":0,"playbackBarBackgroundOpacity":1,"toolTipShadowColor":"#333138","surfaceReticleColor":"#FFFFFF","playbackBarBottom":5,"subtitlesFontColor":"#FFFFFF","paddingRight":0,"surfaceReticleOpacity":0.6,"subtitlesTextShadowVerticalLength":1,"id":"MainViewer","toolTipTextShadowColor":"#000000","toolTipShadowOpacity":1,"toolTipFontFamily":"Arial","translationTransitionDuration":2000,"playbackBarHeight":10,"toolTipFontSize":"1.11vmin","progressLeft":0,"playbackBarBackgroundColor":["#FFFFFF"],"playbackBarHeadBackgroundColorDirection":"vertical","toolTipFontWeight":"normal","playbackBarHeadWidth":6,"toolTipBackgroundColor":"#F6F6F6","playbackBarProgressBackgroundColorDirection":"vertical","subtitlesFontWeight":"normal","playbackBarProgressBorderSize":0,"toolTipBorderSize":1,"playbackBarBackgroundColorDirection":"vertical","toolTipPaddingTop":4,"subtitlesPaddingLeft":5,"surfaceReticleSelectionColor":"#FFFFFF","playbackBarProgressBorderRadius":0,"subtitlesBottom":50,"playbackBarRight":0,"surfaceReticleSelectionOpacity":1,"subtitlesPaddingRight":5,"doubleClickAction":"toggle_fullscreen","vrPointerSelectionColor":"#FF6600","playbackBarProgressBackgroundColor":["#3399FF"],"playbackBarHeadShadowOpacity":0.7,"height":"100%","toolTipShadowVerticalLength":0,"width":"100%","subtitlesTop":0,"minHeight":50,"minWidth":100,"playbackBarProgressBackgroundColorRatios":[0],"vrPointerSelectionTime":2000,"transitionDuration":500,"playbackBarBorderColor":"#FFFFFF","playbackBarBorderRadius":0,"displayTooltipInTouchScreens":true,"playbackBarProgressBorderColor":"#000000","progressBackgroundColorRatios":[0],"subtitlesTextShadowColor":"#000000","subtitlesFontSize":"3vmin","toolTipPaddingBottom":4,"subtitlesPaddingBottom":5,"subtitlesTextShadowHorizontalLength":1,"progressRight":0,"subtitlesBackgroundOpacity":0.2,"playbackBarHeadBorderRadius":0,"toolTipShadowBlurRadius":3,"toolTipFontStyle":"normal","toolTipShadowHorizontalLength":0,"progressOpacity":1,"playbackBarHeadBorderColor":"#000000","class":"ViewerArea","transitionMode":"blending","progressBarBackgroundColorDirection":"vertical","toolTipTextShadowOpacity":0,"subtitlesBorderColor":"#FFFFFF","progressBarBorderColor":"#000000","playbackBarBorderSize":0,"playbackBarProgressOpacity":1,"paddingTop":0,"progressBarBackgroundColorRatios":[0],"paddingBottom":0,"subtitlesEnabled":true,"progressBackgroundColorDirection":"vertical","toolTipPaddingRight":6,"subtitlesTextDecoration":"none","borderRadius":0,"subtitlesTextShadowBlurRadius":0,"subtitlesFontFamily":"Arial","progressBarBackgroundColor":["#3399FF"],"toolTipFontColor":"#606060","toolTipTextShadowBlurRadius":3,"subtitlesPaddingTop":5,"progressBorderColor":"#000000","subtitlesShadow":false,"progressBarOpacity":1,"progressBackgroundColor":["#FFFFFF"],"playbackBarHeadShadowBlurRadius":3,"subtitlesOpacity":1,"playbackBarHeadShadowHorizontalLength":0,"toolTipDisplayTime":600,"firstTransitionDuration":0,"toolTipShadowSpread":0,"playbackBarHeadHeight":15,"progressBottom":0,"subtitlesGap":0,"progressHeight":10,"subtitlesBackgroundColor":"#000000","progressBorderSize":0,"playbackBarLeft":0,"toolTipPaddingLeft":6,"shadow":false,"playbackBarHeadBorderSize":0,"playbackBarHeadBackgroundColorRatios":[0,1],"toolTipBorderColor":"#767676","progressBarBorderSize":0,"displayTooltipInSurfaceSelection":true,"propagateClick":false,"toolTipOpacity":1,"toolTipHorizontalAlign":"center","playbackBarHeadOpacity":1,"subtitlesVerticalAlign":"bottom","playbackBarHeadShadow":true,"subtitlesTextShadowOpacity":1,"subtitlesHorizontalAlign":"center","progressBarBorderRadius":0,"toolTipBorderRadius":3,"playbackBarHeadShadowVerticalLength":0,"data":{"name":"Main Viewer"}},{"automaticZoomSpeed":10,"hoverFactor":0,"initialSequence":{"class":"PanoramaCameraSequence","movements":[{"yawSpeed":1.38,"easing":"quad_in_out","targetYaw":29.87,"targetPitch":4.3,"class":"TargetPanoramaCameraMovement","pitchSpeed":1.28,"path":"shortest"},{"yawSpeed":1.38,"easing":"quad_in_out","targetYaw":-29.88,"targetPitch":5.03,"class":"TargetPanoramaCameraMovement","pitchSpeed":1.28,"path":"shortest","end":"this.mainPlayList.set('selectedIndex', 0)"}],"restartMovementOnUserInteraction":false},"class":"PanoramaCamera","initialPosition":{"class":"PanoramaCameraPosition","yaw":0,"pitch":5.85},"id":"panorama_511EB481_5895_ED1B_41C3_BB36B99D7268_camera"},{"hfov":65,"label":trans('panorama_53A59D81_588D_9F1A_41C3_F46603C7778F.label'),"thumbnailUrl":"media/panorama_53A59D81_588D_9F1A_41C3_F46603C7778F_t.jpg","frames":[{"class":"CubicPanoramaFrame","front":{"class":"ImageResource","levels":[{"height":8192,"width":8192,"url":"media/panorama_53A59D81_588D_9F1A_41C3_F46603C7778F_0/f/0/{row}_{column}.jpg","rowCount":16,"class":"TiledImageResourceLevel","colCount":16,"tags":"ondemand"},{"height":4096,"width":4096,"url":"media/panorama_53A59D81_588D_9F1A_41C3_F46603C7778F_0/f/1/{row}_{column}.jpg","rowCount":8,"class":"TiledImageResourceLevel","colCount":8,"tags":"ondemand"},{"height":2048,"width":2048,"url":"media/panorama_53A59D81_588D_9F1A_41C3_F46603C7778F_0/f/2/{row}_{column}.jpg","rowCount":4,"class":"TiledImageResourceLevel","colCount":4,"tags":"ondemand"},{"height":1024,"width":1024,"url":"media/panorama_53A59D81_588D_9F1A_41C3_F46603C7778F_0/f/3/{row}_{column}.jpg","rowCount":2,"class":"TiledImageResourceLevel","colCount":2,"tags":"ondemand"},{"height":512,"width":512,"url":"media/panorama_53A59D81_588D_9F1A_41C3_F46603C7778F_0/f/4/{row}_{column}.jpg","rowCount":1,"class":"TiledImageResourceLevel","colCount":1,"tags":["ondemand","preload"]}]},"thumbnailUrl":"media/panorama_53A59D81_588D_9F1A_41C3_F46603C7778F_t.jpg"}],"partial":true,"hfovMin":"150%","vfov":48.75,"class":"Panorama","hfovMax":65,"data":{"label":"2"},"pitch":-0.64,"id":"panorama_53A59D81_588D_9F1A_41C3_F46603C7778F"},{"automaticZoomSpeed":10,"hoverFactor":0,"initialSequence":{"class":"PanoramaCameraSequence","movements":[{"yawSpeed":1.38,"easing":"quad_in_out","targetYaw":27.92,"targetPitch":6.09,"class":"TargetPanoramaCameraMovement","pitchSpeed":1.28,"path":"shortest","end":"this.mainPlayList.set('selectedIndex', 3)"},{"yawSpeed":1.38,"easing":"quad_in_out","targetYaw":-29.55,"targetPitch":7.15,"class":"TargetPanoramaCameraMovement","pitchSpeed":1.28,"path":"shortest"}],"restartMovementOnUserInteraction":false},"class":"PanoramaCamera","initialPosition":{"class":"PanoramaCameraPosition","yaw":0,"pitch":7.23},"id":"panorama_5113B17F_5895_A7E7_41D4_C3DEEF750D32_camera"},{"hfov":65,"label":trans('panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7.label'),"thumbnailUrl":"media/panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7_t.jpg","frames":[{"class":"CubicPanoramaFrame","front":{"class":"ImageResource","levels":[{"height":8192,"width":8192,"url":"media/panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7_0/f/0/{row}_{column}.jpg","rowCount":16,"class":"TiledImageResourceLevel","colCount":16,"tags":"ondemand"},{"height":4096,"width":4096,"url":"media/panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7_0/f/1/{row}_{column}.jpg","rowCount":8,"class":"TiledImageResourceLevel","colCount":8,"tags":"ondemand"},{"height":2048,"width":2048,"url":"media/panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7_0/f/2/{row}_{column}.jpg","rowCount":4,"class":"TiledImageResourceLevel","colCount":4,"tags":"ondemand"},{"height":1024,"width":1024,"url":"media/panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7_0/f/3/{row}_{column}.jpg","rowCount":2,"class":"TiledImageResourceLevel","colCount":2,"tags":"ondemand"},{"height":512,"width":512,"url":"media/panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7_0/f/4/{row}_{column}.jpg","rowCount":1,"class":"TiledImageResourceLevel","colCount":1,"tags":["ondemand","preload"]}]},"thumbnailUrl":"media/panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7_t.jpg"}],"partial":true,"hfovMin":"150%","vfov":48.75,"class":"Panorama","hfovMax":60,"data":{"label":"1"},"pitch":4.68,"id":"panorama_522BCC4D_5894_9D2B_41B9_86BD41912FD7"},{"id":"sequence_62E611D3_6F0F_61F3_41AC_587B3AA2BA94","class":"PanoramaCameraSequence","movements":[{"yawSpeed":1.38,"easing":"quad_in_out","targetYaw":-27.52,"targetPitch":1.91,"class":"TargetPanoramaCameraMovement","pitchSpeed":1.28,"path":"shortest"}],"restartMovementOnUserInteraction":false},{"id":"sequence_63C5760B_6F0D_6252_41D8_DCFBE890066A","class":"PanoramaCameraSequence","movements":[{"yawSpeed":1.38,"easing":"quad_in_out","targetYaw":29.3,"targetPitch":-1.37,"class":"TargetPanoramaCameraMovement","pitchSpeed":1.28,"path":"shortest","end":"this.mainPlayList.set('selectedIndex', 2)"},{"yawSpeed":1.38,"easing":"quad_in_out","targetYaw":-29.39,"targetPitch":-2.11,"class":"TargetPanoramaCameraMovement","pitchSpeed":1.28,"path":"shortest"}],"restartMovementOnUserInteraction":false}],"minHeight":0,"defaultVRPointer":"laser","scrollBarMargin":2,"minWidth":0,"shadow":false,"contentOpaque":false,"backgroundPreloadEnabled":true,"propagateClick":false,"toolTipHorizontalAlign":"center","scrollBarVisible":"rollOver","data":{"name":"Player423","textToSpeechConfig":{"speechOnInfoWindow":false,"speechOnQuizQuestion":false,"volume":1,"pitch":1,"speechOnTooltip":false,"stopBackgroundAudio":false,"rate":1},"locales":{"es":"locale/es.txt"},"defaultLocale":"es"},"backgroundColorRatios":[0],"gap":10,"mediaActivationMode":"window"};
if (script['data'] == undefined)
    script['data'] = {};
script['data']['translateObjs'] = translateObjs;
script['data']['history'] = {};
script['scripts']['createQuizConfig'] = createQuizConfig;
TDV['PlayerAPI']['defineScript'](script);
//# sourceMappingURL=script_device_v2022.1.9.js.map
})();
//Generated with v2022.1.9, Thu Jun 16 2022