from django import forms
from django.conf import settings
from .models import Post


class PostForm(forms.ModelForm):
    """Custom form for Post model with dynamic visibility choices"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Set visibility choices based on feature flags
        self.fields['visibility'].choices = Post.get_allowed_visibility_choices()
        
        # Set default to friends if public is disabled
        if not getattr(settings, 'ENABLE_PUBLIC_SHARING', False):
            self.fields['visibility'].initial = 'friends'
        
        # Add CSS classes
        self.fields['title'].widget.attrs.update({'class': 'form-control'})
        self.fields['content'].widget.attrs.update({
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Share your thoughts...'
        })
        self.fields['visibility'].widget.attrs.update({'class': 'form-control'})
        self.fields['file'].widget.attrs.update({'class': 'form-control-file'})
    
    class Meta:
        model = Post
        fields = ['title', 'content', 'file', 'visibility']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 4}),
        }


class PostUpdateForm(PostForm):
    """Form for updating posts"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # If post is currently public but public sharing is disabled,
        # show a warning and change to friends-only
        if (self.instance and 
            self.instance.visibility == 'public' and 
            not getattr(settings, 'ENABLE_PUBLIC_SHARING', False)):
            
            self.fields['visibility'].help_text = (
                "Note: This post was previously public but public sharing "
                "is now disabled. It has been changed to friends-only."
            )
            self.initial['visibility'] = 'friends'
