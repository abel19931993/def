import folium
from folium.plugins import antpath


def ant_map(locations,m,iconProp=None, color =None,targetInormation=None):
    folium.plugins.AntPath(
        locations=locations, reverse="True", dash_array=[20, 30]
    ).add_to(m)
    m.fit_bounds(m.get_bounds())
    if iconProp is not None:
        if targetInormation is not None:
            folium.Marker([locations[-1][0],locations[-1][1]],popup=popup_marker(targetInormation),lazy=True).add_to(m)
        else:
            folium.Marker([locations[-1][0],locations[-1][1]],lazy=True).add_to(m)

    return m
def popup_marker(information=None):
    import base64
    import branca
    encoded = base64.b64encode(open('man.jpg', 'rb').read())
    html = f"""<div><img src="data:image/jpg;base64,{{}}"></br> <p1>{information}</p1></div>""".format
    iframe = branca.element.IFrame(html(encoded.decode('UTF-8')), width=400, height=350)
    popup = folium.Popup(iframe, max_width=200)
    return popup

wind_locations2 = [
    [45.35560, -31.992190],
    [56.178870, -42.89062],
    [47.754100, -43.94531],
    [38.272690, -37.96875],
    [32.069130, -41.13281],
    [16.299050, -36.56250],
    [8.4071700, -30.23437],
    [11.0546300, -22.50000],
    [8.754790, -18.28125],
    [-18.61658, -20.03906],
    [-22.35364, -24.25781],
    [-39.90974, -30.93750],
    [-43.83453, -41.13281],
    [-47.75410, -49.92187],
    [-50.95843, -54.14062],
    [-55.97380, -56.60156],
]


wind_locations = [
    [69.35560, -31.992190],
    [56.178870, -42.89062],
    [47.754100, -43.94531],
    [38.272690, -37.96875],
    [32.069130, -41.13281],
    [16.299050, -36.56250],
    [8.4071700, -30.23437],
    [11.0546300, -22.50000],
    [8.754790, -18.28125],
    [-18.61658, -20.03906],
    [-22.35364, -24.25781],
    [-39.90974, -30.93750],
    [-43.83453, -41.13281],
    [-47.75410, -49.92187],
    [-50.95843, -54.14062],
    [-55.97380, -56.60156],
]

m = folium.Map((10,40))
m = ant_map(wind_locations,m,iconProp='a',targetInormation='Name:Abebe')
ant_map(wind_locations2,m,iconProp='a',targetInormation='Name:Abebe').save('test.html')

