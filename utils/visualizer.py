import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

class LogVisualizer:
    def create_severity_pie_chart(self, df):
        severity_counts = df['severity'].value_counts()
        fig = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            title='Log Severity Distribution',
            color_discrete_sequence=['#00ff00', '#ffff00', '#ff0000']
        )
        return fig

    def create_timeline_chart(self, df):
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        timeline_data = df.groupby([df['timestamp'].dt.date, 'severity']).size().reset_index(name='count')
        
        fig = px.line(
            timeline_data,
            x='timestamp',
            y='count',
            color='severity',
            title='Event Timeline',
            labels={'timestamp': 'Date', 'count': 'Number of Events'},
            color_discrete_sequence=['#00ff00', '#ffff00', '#ff0000']
        )
        return fig

    def create_ip_bar_chart(self, df, top_n=10):
        ip_counts = df['ip_address'].value_counts().head(top_n)
        fig = px.bar(
            x=ip_counts.index,
            y=ip_counts.values,
            title=f'Top {top_n} IP Addresses',
            labels={'x': 'IP Address', 'y': 'Number of Events'},
            color_discrete_sequence=['#ff4b4b']
        )
        return fig

    def create_anomaly_scatter(self, features, anomalies):
        fig = px.scatter(
            features,
            x='hour',
            y='severity_score',
            color=anomalies.astype(str),
            title='Anomaly Detection Results',
            labels={'hour': 'Hour of Day', 'severity_score': 'Severity Score'},
            color_discrete_map={'True': '#ff0000', 'False': '#00ff00'}
        )
        return fig
